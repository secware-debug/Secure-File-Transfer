import os, sys
sys.path.append(".")
sys.path.append("..")

import base64
import logging as log
import ntpath
import socket
import threading

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from project1_keyutils import keyUtils
from project1_settingsParser import settingsParser

"""
   SENDER:
   This class is used to establish a connection to a remote host and then securely transmit a file using a combination
   of public encryption, symmetric encryption, and hashing. The overall protocol is custom, but attempts to follow
   the basic structure of an HTTPS connection. The chief difference is that there is no support of certificates.

   RECEIVER:
   This class is used as a server that will use a combination of public encryption, symmetric encryption, and hashing
   to securely accept a file from a remote host from man-in-the-middle or other interception attacks. The overall
   protocol is custom, but essentially mirrors the structure of an HTTPS connection.
   
   KEYUTILS:
   This class is used to create, save, and import RSA and AES keys. It can be run standalone to create a set of
   raneom RSA and AES keys, or used on demand as a library.


   GENERAL PROCESS AND COMMUNICATION FLOW:

   SENDER:
   Establish a remote socket connection
       Generate a random RSA key pair
       Send the remote host the public RSA key
       Wait for the remote host to respond back with a symmetric AES key encrypted with the public RSA cipher
       Get a file ready to transmit
           Generate the SHA256 hash of the file and store it as a message digest ("message-dd")
           Encrypt (digitally sign) the message digest using the RSA private key ("message.ds-msg")
           Append the file to the digital signature and encrypt them with the AES key ("message.aescipher)
       Send the encrypted package to the remote host
       Wait for the remote host to confirm that the signature matches


   RECEIVER:
   Create a TCP socket and listen for a remote host
   When a remote host connects, establish a connection and start a new thread
       Wait for the remote host to send a public RSA key
       Generate a random symmetric AES cipher
       Encrypt the AES key with the sender's public key
       Send the encrypted AES key to the remote host
       Receive an encrypted package from the remote host and save it to disk (message.aescipher)
       Read the encrypted file block by block and do the following:
           Decrypt each block using the AES key
           The first 256 bytes contain the digital signature. Save this to memory
           The rest of the blocks contain the binary data. For each of these blocks
               Append them to a file ("decrypt_X")
               Update a SHA256 message digest
       After the file has been read and decrypted:
           Write the SHA256 has value to disk (message.dd)
           Use the calculated message digest and RSA public key to verify the digital signature
           Send the remote host a message stating if the verification was successful


   CONFIGURATION:
   Configuration information and settings are stored in XML files. Socket addresses, file name and storage locations,
   packet and buffer sizes, log formats, etc can be customized by editing the XML document. Note: Some settings such
   as the modes for AES and RSA encryption are for information purposes only. Changing them will not effect the
   behavior of the program.


   LOG FILES:
   All communication and internal messages are stored in log files. There is no console output. In addition to process
   information, the log files will contain the message digests and digital signatures. The log files also contain both
   the raw binary data and base16 encoded values for the AES symmetric key and the corresponding IV. Since the AES key
   is chosen at random for each transfer, publishing the information in the log is not a strong security risk.


   USE:
   There are three separate programs: receiver, sender, and keyUtils. The receiver and sender must be run together, but
   the keyUtils program can be run on its own.

       KeyUtils:   python3 keyUtils.py
       Running this program will generate RSA and AES keys. It will store these as three files. The path to these files
       can be specified in config_keyUtils.xml. NOTE: It is not necessary to run this program before running the
       receiver or sender applications. The receiver or sender will look for a key file when needed, and if one cannot
       be located, it will generate whatever is required.

       Sender/Receiver:
       1. Start the receiver (server) with     python3 server.py
       2. Obtain the IP address of the receiver
       3. Edit the config_sender.py file and make the following changes:
           A. Replace the remote and port values with the values from the server
           B. If you want to prompt the user to specify the file to be sent, set requestFileInput to "true"
              Or, you can set requestFileInput to "false" and set the value of testFile to the path of the
              file you want to upload.
           C. If you want to allow the encrypted signature+file file to be modified before being transmitted,
              set pauseBeforeSend to "true"
           D. Change the file names for paths as needed
       4. Start the sender with    python3 sender.py


   NOTES:

   1. The module supports the sending and checking of files of any length, regardless of system memory. However, the
   Python implementation of AES encryption and SHA hashing is not as efficient as it would be in a lower level langauge
   such as C or C++. As such, the time involved for cryptographic operations on larger files can be long.
   During tests, the process took around 5 minutes to complete on a 1GB video file.

   2. DO NOT USE THIS TO TRANSMIT SENSITIVE INFORMATION.
   This module IS NOT designed to be used in any kind of real world application. Although the underlying
   cryptographic operations are based on well-known and presumably secure standards, the module uses these protocols
   in a custom manner. this customization almost cardinally introduces numerous attack vectors and security holes.

   LICENSE:
   Fully open. You can use, modify, and distribute this software without any restriction, implied or otherwise
   """


settings = {}

"""
TODO:
    Refactor settings as non-global
    Refactor importSettings to return a value instead of setting a global
    Extract duplicate methods (send/receive) to a shared class
    
"""


def importSettings(filename: str):
    """
    Parses an xml document for configuration and settings. Settings are stored as <settings>
    elements under the <receiver_settings> tag. The options are kept as name=value pairs.
    :param filename: the filename of the XML document
    :return none
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
    '''
    Loop forever, accepting connections until program is manually terminated
    :param sock: The socket to bind
    :return:
    '''
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
    Must override two functions. __init()__ and run(). Run() will be called when Thread.start() is called
    '''

    _BUFFER_SIZE = None
    _file_count = 1

    @staticmethod
    def make_directory(filename):
        log.info("Checking to see if directory exists for file {} and creating it if needed".format(filename))
        os.makedirs(os.path.dirname(filename), exist_ok=True)

    def __init__(self, connection: socket.socket, remote: str, id: int):
        super().__init__()      # chain call to parent constructor
        self.socket = connection
        self.remote_address = remote
        self.connection_id = id
        ThreadedReceiver._BUFFER_SIZE = int(settings["bufferSize"])

    def send_message(self, text: str):
        """
        Sends a text-based message to the remote host. Using the simple protocol of appending a '\n' to the
        end of the message. As such, messages must not already end with a '\n' or they will not properly received.
        Messages that contain a newline within should be ok, but there is a very small chance that the underlying OS
        socket operations will break the message up in such a way that a chunk is transmitted with the newline at the
        end of a segment. This will cause the receiver to believe that the message has been fully transmitted.
        :param text: the message to be sent
        :return:
        """
        log.info("--> {}".format(text))
        self.socket.send((text + '\n').encode('utf-8'))

    def receive_message(self) -> str:
        """
        Pulls from the socket, appending the to a string until the string ends with a '\n'. The string is then
        returned, but without the ending newline. See notes on send_message
        :return: the message that was received
        """
        msg = ''
        while not msg.endswith('\n'):
            msg += str(self.socket.recv(ThreadedReceiver._BUFFER_SIZE), 'utf-8')
        msg = msg[:len(msg) - 1]
        log.info("<-- {}".format(msg))
        return msg

    def send_file(self, path):
        """
        Transmits a file to the remote host. Binary mode is used, so all files and file types are supported.
        The protocol is to transmit the name of the file as a message, the size of the file as a message, and then
        the file itself.
        :param path: text path of the file to be sent
        :return:
        """
        filename = ntpath.basename(path)
        size = os.path.getsize(path)
        log.info("Preparing to send ({}) of size {:d} bytes".format(filename, size))
        self.send_message(filename)
        self.send_message(str(size))
        with open(path, mode='rb') as f:
            for chunk in iter((lambda: f.read(ThreadedReceiver._BUFFER_SIZE)), b''):
                self.socket.send(chunk)
        log.info("Finished transmitting file")

    def receive_file(self) -> str:
        """
        Receives a binary file from a remote host. The protocol is to first listen for a message that contains
        the file name, followed by a message containing the size of the file, and then multiple messages containing
        the actual binary data.
        :return: the path to the received file
        """

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
                chunk = self.socket.recv(ThreadedReceiver._BUFFER_SIZE)
                f.write(chunk)
                bytes_remaining -= len(chunk)
        log.info("...receive complete")

        return path



    def import_rsa_key(self, filename) -> RSA._RSAobj:
        """
        Imports an RSA key file and creates and returns an RSA key object. The resulting key can always be used for
        public operations, and can be used for private operations if the imported key file contained the private
        key values.
        :return: An RSA key object
        """
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

        """
        This method will be called when Thread.start() is called. Each call will result in a new
        thread being created.
        The main routine of the program. See outline .txt for a full process flow.
        """

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
        log.info("...key:\t{}".format(str(aes_key)))
        log.info("... iv:\t{}".format(str(aes_iv)))

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
        # Decrypt the digital signature and store it in memory for later
        # Write the unencrypted file to disk
        dig_sig_as_bin_str = None
        sha_hash = SHA256.new()
        sig_size = int(settings["signatureSize"])
        log.info("Opening encrypted file")
        with open(enc_filename, mode='rb') as f1:
            log.info("Extracting and decrypting digital signature")
            enc_sig = f1.read(sig_size)
            base16_enc_dig_sig = aes_cipher.decrypt(enc_sig)

            sig_as_str = str(base16_enc_dig_sig, 'utf-8')
            length = len(sig_as_str)
            half = int((length - 12) / 2)
            log.info('\n' + '*' * half + "RCVD SIGNATURE" + '*' * half + "\n{}\n".format(sig_as_str) +
                     '*' * half + "*LENGTH = {:d}*".format(length) + "*" * half)
            dig_sig_as_bin_str = base64.b16decode(base16_enc_dig_sig)

            results_directory = settings["resultsDirectory"]
            new_baseame = settings['decryptedFilePrefix'] + str(ThreadedReceiver._file_count)
            new_filename = os.path.join(results_directory, new_baseame)
            os.makedirs(os.path.dirname(new_filename), exist_ok=True)
            ThreadedReceiver._file_count += 1

            with open(new_filename, mode='wb') as f2:
                for enc_chunk in iter((lambda: f1.read(ThreadedReceiver._BUFFER_SIZE)), b''):
                    dec_chunk = aes_cipher.decrypt(enc_chunk)
                    sha_hash.update(dec_chunk)
                    f2.write(dec_chunk)

        # Write the message digest as a hex encoded value to log and to file 'message.dd'
        hash_file = settings["hashFile"]
        log.info("Writing message digest to file {}".format(hash_file))
        log.info("Checking to see if directory exists for file {} and creating it if needed".format(hash_file))
        os.makedirs(os.path.dirname(hash_file), exist_ok=True)
        hash_as_hex_str = sha_hash.hexdigest().upper()
        log.info('\n' + '*' * 27 + "SHA256 HASH" + '*' * 27 + "\n{}\n".format(hash_as_hex_str) +
                 '*' * 27 + "LENGTH = {:d}".format(len(hash_as_hex_str)) + "*" * 27)
        with open(hash_file, mode='w') as f:
            f.write(hash_as_hex_str)

        # Verify that calculated hash matches the digital signature that was sent
        self.receive_message()
        log.info("Verifying that signature matches calculated hash...")
        cypher = PKCS1_v1_5.new(pub_key)
        is_match = cypher.verify(sha_hash, dig_sig_as_bin_str)
        if is_match:
            msg = "\n    __  __     _     _____    ___   _  _ \n   |  \/  |   /_\   |_   _|  / __| | || |\n   | |\/| |  / _ \    | |   | (__  | __ |\n   |_|  |_| /_/ \_\   |_|    \___| |_||_|\n"
            self.send_message("true")
        else:
            msg = "\n___     ___    ___   ___             \n  / _ \   / _ \  | _ \ / __|            \n | (_) | | (_) | |  _/ \__ \  _   _   _ \n  \___/   \___/  |_|   |___/ (_) (_) (_)\n"
            self.send_message('false')
        log.info(msg)





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

