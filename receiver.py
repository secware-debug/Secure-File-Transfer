import socket
import threading
from xml.dom import minidom
import logging as log
import settingsParser
import os
import ntpath
from Crypto.PublicKey import RSA
import keyUtils
from Crypto.Cipher import PKCS1_OAEP
import base64

settings = {}


def importSettings(filename):
    """
    Parses an xml document for configuration and settings. Settings are stored as <settings>
    elements under the <receiver_settings> tag. The options are kept as name=value pairs.
    the value.
    :param filename:
    :return dictionary of settings:
    """
    global settings
    settings = settingsParser.parse(filename, "receiver_settings", "setting")


def init():
    # import settings from XML file
    importSettings("config_receiver.xml")
    log.basicConfig(filename=settings["logFile"], filemode=settings["logMode"], level=int(settings["logLevel"]),
                        format=settings["logFormat"])

    log.info("Receiver started. Settings loaded")
    log.debug("Settings:" + str(settings)+'\n')

    # initialize socket
    # socket constructor takes a tuple of (address, port)
    port = int(settings["port"])
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('localhost', port))

    print("Listening on port {:d} for new connections:".format(port))
    sock.listen()
    log.info("The host is listening for new connections on port {:d}".format(port))

    accept_connections(sock)


def accept_connections(sock : socket):
    socket_id = 1

    while True:
        connection, remote_address = sock.accept()
        msg = "Accepted a new connection from {}:{}".format(remote_address[0], remote_address[1])
        log.info(msg)
        print(msg)

        receiver = ThreadedReceiver(connection, remote_address, socket_id)
        receiver.start()
        socket_id += 1


class ThreadedReceiver(threading.Thread):
    '''
    Inherits from the Thread class which makes setting up multi-threading simple.
    Must override two functions. __init()_ and run(). Run() will be called when Thread.start() is called
    '''

    BUFFER_SIZE = 8096
    __file_count = 1

    @staticmethod
    def make_directory(filename):
        log.info("Checking to see if directory exists for file {} and creating it if needed".format(filename))
        os.makedirs(os.path.dirname(filename), exist_ok=True)

    def __init__(self, connection: socket.socket, remote: str, id: int):
        super().__init__()      # chain call to parent constructor
        self.socket = connection
        self.remote_address = remote
        self.connection_id = id

    def send_message(self, text: str):
        log.info("--> {}".format(text))
        self.socket.send((text + '\n').encode('utf-8'))

    def receive_message(self) -> str:
        msg = ''
        while not msg.endswith('\n'):
            msg += str(self.socket.recv(ThreadedReceiver.BUFFER_SIZE), 'utf-8')
        msg = msg[:len(msg) - 1]
        log.info("<-- {}".format(msg))
        return msg

    def send_file(self, path):
        filename = ntpath.basename(path)
        size = os.path.getsize(path)
        log.info("Preparing to send ({}) of size {:d} bytes".format(filename, size))
        self.send_message(filename)
        self.send_message(str(size))
        with open(path, mode='rb') as f:
            for chunk in iter((lambda: f.read(ThreadedReceiver.BUFFER_SIZE)), b''):
                self.socket.send(chunk)
        log.info("Finished transmitting file")

    def receive_file(self) -> str:
        dir_name = settings["receiveDirectory"]
        log.info("Receiving file:...")
        filename = self.receive_message()
        size = int(self.receive_message())
        log.info("...Filename: {}  Size: {:d}".format(filename, size))

        path = os.path.join(dir_name, filename)
        self.make_directory(path)

        with open(path, mode='wb') as f:
            bytes_remaining = size
            while bytes_remaining:
                chunk = self.socket.recv(ThreadedReceiver.BUFFER_SIZE)
                f.write(chunk)
                bytes_remaining -= len(chunk)
        log.info("...receive complete")

        return path


    # def send_RSA_encrypted_message(self, cipher: PKCS1_OAEP.PKCS1OAEP_Cipher, message: str):
    #     log.info("Sending encrypted message")
    #     enc_msg = cipher.encrypt(message.encode('utf-8'))
    #     self.send_message(enc_msg)


    def import_rsa_key(self, filename) -> RSA._RSAobj:
        log.info("Importing cryptographic key from {} ...".format(filename))
        ku = keyUtils.KeyUtils()
        key = ku.import_key_from_file(filename)
        log.info("...key import success")
        return key

    def cleanup(self):
        log.info("Operations complete. Cleaning up")
        log.info("Closing socket")
        self.socket.close()
        print("Socket Closed")

    def run(self):
        log.info("Thread #{} created and started".format(self.connection_id))

        # Wait for sender to msg that public key is ready to be sent, and then acknowledge
        log.info("Waiting for sender to get public key ready...")
        m = self.receive_message()
        self.send_message("ack")

        # receive the public key and send acknowledgement
        pub_key_path = self.receive_file()
        self.send_message("ack")

        # Instantiate a new RSA key and use it to encrypt the AES symmetric key
        log.info("Creating a new RSA cipher instance from imported key")
        pub_key = self.import_rsa_key(pub_key_path)
        pub_cipher = PKCS1_OAEP.new(pub_key)

        # Generate a new random AES key
        log.info("Generating a random AES key...")
        ku = keyUtils.KeyUtils()
        aes_cipher, aes_key, aes_iv =  ku.generate_random_AES_key()
        log.info("...key: {}".format(str(aes_key)))
        log.info("...iv: {}".format(str(aes_iv)))

        # Encrypt and encode the AES key and IV
        log.info("Encrypting and encoding the AES key and IV")
        encrypted_key = pub_cipher.encrypt(aes_key)
        encoded_cypher_key = str(base64.b16encode(encrypted_key), 'utf-8')
        encrypted_iv = pub_cipher.encrypt(aes_iv)
        encoded_cypher_iv = str(base64.b16encode(encrypted_iv), 'utf-8')

        # Send message saying encrypted key is ready to be sent and wait for acknowledgement
        self.send_message("Ready to send encrypted AES key")
        self.receive_message()

        # Send the encoded cyphertext and wait for confirmation that they were received
        log.info("Sending AES information")
        self.send_message(encoded_cypher_key)
        self.send_message(encoded_cypher_iv)
        m = self.receive_message()

        # Wait for message saying that encrypted file is ready to be transmitted and acknowledge
        m = self.receive_message()
        self.send_message('ack')

        # Receive encrypted file and acknowledge
        log.info("Receiving encrypted file")
        enc_filename = self.receive_file()
        self.send_message('ack')

        # Decrypt the file, extracting the digital signature in the process
        # Decrypt the digital signature and keep the contents in memory
        # Write the unencrypted file to disk
        orig_hash = ''
        sig_size = int(settings["signatureSize"])
        log.info("Opening encrypted file")
        with open(enc_filename, mode='rb') as f:
            log.info("Extracting and decrypting digital signature")
            enc_sig = f.read(sig_size)
            base16_enc_dig_sig = aes_cipher.decrypt(enc_sig)
            log.info('\n' + '*' * 25 + "RCVD SIGNATURE" + '*' * 25 + "\n{}\n".format(str(base16_enc_dig_sig, 'utf-8')) +
                     '*' * 25 + "LENGTH = {:d}".format(len(base16_enc_dig_sig)) + "*" * 25)

            decoded_dig_sig = base64.b16decode(base16_enc_dig_sig)
            orig_hash = str(pub_cipher.encrypt(decoded_dig_sig), 'utf-8')
            log.info('\n' + '*' * 25 + "ORIGINAL HASH" + '*' * 25 + "\n{}\n".format(orig_hash) +
                     '*' * 25 + "LENGTH = {:d}".format(len(orig_hash)) + "*" * 25)








        '''      
        
        Y		Read encrypted file from disk block by block
                Decrypt block using yAES object
                Extract first XX bytes and save in memory as hash
                Write remaining blocks/data to <filename>
        
        Y		Calculate SHA256 hash value on remaining blocks/data
                Write calculated hash to log file in base-16
        
        Y		Initialze RSA object using publicX.key
        
        Y		Use publicX key to decrypt encrypted hash
                Write decrypted hash to disk as "message.dd"
        
        Y		Compare calculated hash to decrypted hash and write results to log
        
        -->		Send X a message stating if the file transfer was successful (hash values match)
        
        Y		Close connection

        '''



        self.cleanup()



if __name__ == "__main__":
    init()

