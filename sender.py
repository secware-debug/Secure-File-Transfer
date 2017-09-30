import logging as log
import socket
from xml.dom import minidom
import settingsParser
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
import keyUtils
import io
import os
import binascii
import base64
import ntpath

DEBUG = True
TESTFILE1 = "test_file_1.txt"




# noinspection PyProtectedMember
class Sender:

    BUFFER_SIZE = 8096

    @staticmethod
    def make_directory(filename):
        log.info("Checking to see if directory exists for file {} and creating it if needed".format(filename))
        os.makedirs(os.path.dirname(filename), exist_ok=True)

    @staticmethod
    def write_text_file(filename, text):
        with open(file=filename, mode='w') as f:
            f.write(text)

    def __init__(self):
        self.settings = {}
        self.reader = None  # type: io.BufferedReader
        self.socket = None  # type: socket.socket
        self.sha_hash = ""
        pass

    def init(self):
        self.parse_settings("config_sender.xml")
        self.init_log()
        log.info("Sender created. Settings parsed")

        log.info("Attempting to connect to remote host...")
        self.socket = self.create_connection()

    def init_log(self):
        d = self.settings
        log.basicConfig(filename=d["logFile"], filemode=d["logMode"], level=int(d["logLevel"]),
                        format=d["logFormat"])

    def parse_settings(self, file: str):
        self.settings = settingsParser.parse(file, "sender_settings", "setting")

    def create_connection(self) -> socket.socket:
        addr = self.settings["remote"]
        port = int(self.settings["port"])

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # type: socket.socket

        try:
            sock.connect((addr, port))
            log.info("Connected to {:s}:{:d}".format(addr, port))
            return sock
        except Exception as e:
            log.error(e)

    def send_message(self, text: str):
        log.info("--> {}".format(text))
        self.socket.send((text + '\n').encode('utf-8'))

    def receive_message(self) -> str:
        msg = ''
        while not msg.endswith('\n'):
            msg += str(self.socket.recv(Sender.BUFFER_SIZE), 'utf-8')
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
            for chunk in iter((lambda: f.read(Sender.BUFFER_SIZE)), b''):
                self.socket.send(chunk)
        log.info("Finished transmitting file")

    def receive_file(self):
        dir_name = self.settings["receiveDirectory"]
        log.info("Receiving file:...")
        filename = self.receive_message()
        size = int(self.receive_message())
        log.info("...Filename: {}  Size: {:d}".format(filename, size))

        path = os.path.join(dir_name, filename)
        self.make_directory(path)

        with open(path, mode='wb') as f:
            bytes_remaining = size
            while bytes_remaining:
                chunk = self.socket.recv(Sender.BUFFER_SIZE)
                f.write(chunk)
                bytes_remaining -= len(chunk)
        log.info("...receive complete")



    def import_rsa_key(self) -> RSA._RSAobj:
        prv_file = self.settings["RSAPrivateFile"]
        log.info("Importing RSA key from {}".format(prv_file))

        try:
            ku = keyUtils.KeyUtils()
            key = ku.import_key_from_file(prv_file)
            log.info("Key successfully imported")
            return key
        except Exception as e:
            log.error(e)

    def open_file(self, filename):
        try:
            log.info("Opening file {} for reading".format(filename))
            self.reader = open(file=filename, mode="rb")
            return self.reader
        except Exception as e:
            log.error(e)

    def get_sha256_hash(self, file, buffer_size=8096):
        log.info("Creating new SHA256 instance")
        sha_hash = SHA256.new()

        # loop through bytes of file and update hash accordingly.
        # default chunk size is 8KB
        # iter() can take two arguments: a callable and a value. The lambda wraps the read method as a callable, and the
        #   second argument is an emtpy byte string. Iter will continue to call callable until empty bytes are returned
        log.info("Reading file in blocks of {:d} and generating hash".format(buffer_size))
        for chunk in iter((lambda: file.read(buffer_size)), b''):
            sha_hash.update(chunk)

        log.info('\n' + '*' * 25 + "SHA256 HASH" + '*' * 25 + "\n{}\n".format(sha_hash.hexdigest().upper()) + '*' * 61)
        return sha_hash

    def get_rsa_signature(self, digest_as_string: str, key: RSA._RSAobj) -> str:
        log.info("Generating RSA signature using private key")
        log.info("\t Performing encryption")
        cipher = PKCS1_OAEP.new(key)

        # sig_as_bin = cipher.encrypt(digest_as_string.encode('utf-8'))
        # alternate signature generation using pure RSA without any padding protocol
        sig_as_bin = key.sign(digest_as_string.encode('utf-8'), '')[0]

        # encode the signature with base64
        sig_as_str = base64.b16encode(sig_as_bin).decode('utf-8')
        log.info('\n' + '*' * 25 + "SIGNATURE" + '*' * 25 + "\n{}\n".format(sig_as_str) +
                 '*' * 25 + "LENGTH = {:d}".format(len(sig_as_str)) + "*" * 25)

        # --- Code to test decoding and decryption of hash ---
        decoded_sig = base64.b16decode(sig_as_str)
        decrypted_sig = str(cipher.decrypt(decoded_sig), 'utf-8').upper()
        log.info("\n------\n{}\n-------".format(decrypted_sig))


        return sig_as_str


    def cleanup(self):
        log.info("Cleaning up")

        log.info("Closing socket connection")
        if self.socket:
            self.socket.close()

        log.info("Closing file reader")
        if self.reader:
            self.reader.close()

    def main(self):
        self.init()

        # import RSA key
        rsa_key = self.import_rsa_key()

        # Get filename from user and try to open it
        if DEBUG:
            filename = TESTFILE1
        else:
            filename = input("Enter the path of the file or message: ")

        pt_file = self.open_file(filename)


        # Calculate the SHA256 hash value of the file
		# Store the hash as a file named "message.dd" (configured in sender settings)
        sha_hash = self.get_sha256_hash(pt_file)
        filename = self.settings["hashFile"]
        Sender.make_directory(filename)
        log.info("Writing SHA256 digest to {}".format(filename))
        Sender.write_text_file(filename, sha_hash.hexdigest().upper())

        # Encrypt the hash with senders private key, call it the digital signature
		# Write the digital signature (in base-16) to the log file. (used base-64)
        # Store the digital signature as a file named "message.ds-msg"
        digital_sig = self.get_rsa_signature(sha_hash.hexdigest(), rsa_key)
        filename = self.settings["signatureFile"]
        Sender.make_directory(filename)
        log.info("Writing digital signature to file {}".format(filename))
        Sender.write_text_file(filename, digital_sig)

        # Tell receiver ready to transmit and wait for an 'ack'
        self.send_message("Ready to send public key")
        response = self.receive_message()

        # Transmit publicKey
        pub_file = self.settings["RSAPublicFile"]
        self.send_file(pub_file)

        # Wait for confirmation that key received
        self.receive_message()

        # Wait for message from receiver saying that AES key is ready to be transmitted and send acknowledgment
        self.receive_message()
        self.send_message('ack')

        # Receive encoded and encrypted AES key and IV and send acknowledgment
        encoded_cipher_key = self.receive_message()
        encoded_cipher_iv = self.receive_message()
        log.info("Encoded and encrypted key and IV received...")
        log.info("... key: {}".format(encoded_cipher_key))
        log.info("... iv: {}".format(encoded_cipher_iv))
        self.send_message("ack")

        # Decode and decrypt key and IV
        log.info("Decoding and decrypting key and iv...")
        cipher_key = base64.b16decode(encoded_cipher_key)
        cipher_iv = base64.b16decode(encoded_cipher_iv)
        rsa_cipher = PKCS1_OAEP.new(rsa_key)
        aes_key = rsa_cipher.decrypt(cipher_key)
        aes_iv = rsa_cipher.decrypt(cipher_iv)
        log.info("... key: {}".format(str(aes_key)))
        log.info("... iv: {}".format(str(aes_iv)))

        # Initialize new AES cipher using key
        mode = int(self.settings["AESMode"])
        segmentSize = int(self.settings["AESSegmentSize"])
        aes_cipher = AES.new(key=aes_key, mode=mode, IV=aes_iv, segment_size=segmentSize)
        log.info("AES Cipher loaded")

        # Produce enc(AES_cipher, dig_signature + message_file)
        log.info("Producing the encrypted version of (digital_sig + message) file")
        out_file = self.settings["encryptedFile"]
        Sender.make_directory(out_file)

        with open(out_file, mode='wb') as f:
            enc_sig = aes_cipher.encrypt(digital_sig)
            f.write(enc_sig)
            pt_file.seek(0)
            for plain_chunk in iter(lambda: pt_file.read(Sender.BUFFER_SIZE), b''):
                enc_chunk = aes_cipher.encrypt(plain_chunk)
                f.write(enc_chunk)

        # If option is enabled, pause the program to allow modification of encrypted file before transmission
        should_pause = bool(self.settings['pauseBeforeSend'].lower() is 'yes')
        if should_pause:
            input("Press return when you are ready to transmit the encrypted signature+message file")

        # Alert receiver that file is ready for transmission and wait for acknowledgment
        self.send_message("Encrypted file is ready to be transmitted")
        self.receive_message()

        # Send encrypted file and wait for ack that it was received
        self.send_file(out_file)
        self.receive_message()






        '''
        Sender:

        <--		Wait for response from Y confirming hash

        X		Close connection
        '''


        # '''
        # Append the message byte array to the digital signature byte array
        # Call this new array hashAndMessage
        # '''
        # sig_as_bin = digital_sig.encode('utf-8').upper()
        # print(sig_as_bin)
        # print(len(sig_as_bin))
        # with open("xxx.bin", mode='wb') as f:
        #     f.write(sig_as_bin)
        #     pt_file.seek(0)
        #     for block in iter((lambda: pt_file.read(1024)), b''):
        #         f.write(block)
        #
        # print("")
        #
        # encoded_hash = b''
        # with open("xxx.bin", mode='rb') as f:
        #     encoded_hash = f.read(256)
        #
        #     with open("yyy.bin", mode='wb') as f2:
        #         for block in iter((lambda: f.read(1024)), b''):
        #             f2.write(block)
        #
        # decoded_hash = base64.b16decode(encoded_hash)
        # cipher = PKCS1_OAEP.new(rsa_key)
        # decrypt_hash = str(cipher.decrypt(decoded_hash), 'utf-8')
        #
        # hash1 = decrypt_hash.upper()
        # hash2 = self.get_sha256_hash(open('yyy.bin', 'rb')).hexdigest().upper()
        # print(hash1 == hash2)
        #
        #
        # print(hash1)
        # print(hash2)






        self.cleanup()



if __name__ == "__main__":
    Sender().main()
