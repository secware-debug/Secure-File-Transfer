import sys, os
sys.path.append(".")
sys.path.append("..")

import base64
import io
import logging as log
import ntpath
import socket
import time

from Crypto.Cipher import AES
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
random RSA and AES keys, or used on demand as a library.


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

# noinspection PyProtectedMember
class Sender:


    '''
    TODO:
        Make _BUFFER_SIZE an instance variable since it is configured in settings
        
    '''

    _BUFFER_SIZE = None

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


    def init(self):
        self.parse_settings("config_sender.xml")
        Sender._BUFFER_SIZE = int(self.settings["bufferSize"])

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
            msg += str(self.socket.recv(Sender._BUFFER_SIZE), 'utf-8')
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
        m = self.receive_message()
        with open(path, mode='rb') as f:
            for chunk in iter((lambda: f.read(Sender._BUFFER_SIZE)), b''):
                self.socket.send(chunk)
        log.info("Finished transmitting file")

    def receive_file(self):
        """
        Receives a binary file from a remote host. The protocol is to first listen for a message that contains
        the file name, followed by a message containing the size of the file, and then multiple messages containing
        the actual binary data.
        :return: the path to the received file
        """
        dir_name = self.settings["receiveDirectory"]
        log.info("Receiving file:...")
        filename = self.receive_message()
        size = int(self.receive_message())
        self.send_message("ack")
        log.info("...Filename: {}  Size: {:d}".format(filename, size))

        path = os.path.join(dir_name, filename)
        self.make_directory(path)

        with open(path, mode='wb') as f:
            bytes_remaining = size
            while bytes_remaining:
                chunk = self.socket.recv(Sender._BUFFER_SIZE)
                f.write(chunk)
                bytes_remaining -= len(chunk)
        log.info("...receive complete")



    def import_rsa_key(self) -> RSA._RSAobj:
        """
        Imports an RSA key file and creates and returns an RSA key object. The resulting key can always be used for
        public operations, and can be used for private operations if the imported key file contained the private
        key values.
        :return: An RSA key object
        """
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

    def get_sha256_hash(self, file, buffer_size=8096) -> SHA256.SHA256Hash:
        """
        Generates the SHA256 hash of a file by reading the file block by block and updating accordingly.
        :param file: the text path to the file
        :param buffer_size: the buffer or block size to read
        :return: the SHA256 hash object
        """
        log.info("Creating new SHA256 instance")
        sha_hash = SHA256.new()

        # loop through bytes of file and update hash accordingly.
        # default chunk size is 8KB
        # iter() can take two arguments: a callable and a value. The lambda wraps the read method as a callable, and the
        #   second argument is an emtpy byte string. Iter will continue to call callable until empty bytes are returned
        log.info("Reading file block by block and generating hash (Block size = {:d} bytes".format(buffer_size))
        for chunk in iter((lambda: file.read(buffer_size)), b''):
            sha_hash.update(chunk)

        hash_as_str = sha_hash.hexdigest().upper()
        length = len(hash_as_str)
        half = int((length - 10) / 2)
        log.info('\n' + '*' * half + "SHA256 HASH" + '*' * half + "\n{}\n".format(hash_as_str) +
                 "*" * half + "LENGTH = {:d}".format(length) + "*" * half)
        return sha_hash

    def get_rsa_signature(self, digest: str, key: RSA._RSAobj) -> str:
        """
        Generates a digital signature by signing a message digest with a private key. Please note that while any type\
        of data can be signed, only data that corresponds to one of the PyCrypto.Hash types can be later verified.
        This method also tests for encoding errors bu making sure that the digital signature can be verified after
        being encoded as base16.
        :param digest: The message digest encoded as a base16 string.
        :param key: The RSA key used for signing. Must contain private components.
        :return: A base16 encoded signature
        """
        log.info("Generating RSA signature using private key")
        log.info("\t Performing encryption")
        cipher = PKCS1_v1_5.new(key)
        sig_as_bin_str = cipher.sign(digest)

        # encode the signature as base16
        sig_as_base16_str = base64.b16encode(sig_as_bin_str).decode('utf-8')
        length = len(sig_as_base16_str)
        half = int((length - 12) / 2)
        log.info('\n' + '*' * half + "**SIGNATURE*" + '*' * half + "\n{}\n".format(sig_as_base16_str) +
                 '*' * half + "LENGTH = {:d}".format(length) + "*" * half)

        # --- Code to test decoding and decryption of hash ---
        decoded_sig = base64.b16decode(sig_as_base16_str)
        match = cipher.verify(digest, decoded_sig)
        log.info("\n-------TEST VERIFICATION---------\n{}\n".format(match) + '-' * 35)

        return sig_as_base16_str


    def cleanup(self):
        """
        Closes socket connections and file handles
        :return:
        """
        log.info("Cleaning up")

        log.info("Closing socket connection")
        if self.socket:
            self.socket.close()

        log.info("Closing file reader")
        if self.reader:
            self.reader.close()

    def main(self):
        self.init()

        """
        The main routine of the program. See outline .txt for a full process flow.
        """

        # check to see if key file exists; if not, generate a new pair
        key_file = self.settings["RSAPrivateFile"]
        if not os.path.exists(key_file):
            ku = keyUtils.KeyUtils()
            key = ku.generate_rsa_key_pair()
            ku.write_rsa_keys_to_file(key)


        # import RSA key
        rsa_key = self.import_rsa_key()

        # Get filename from user and try to open it
        request_input = self.settings['requestFileInput'] == 'true'
        if not request_input:
            filename = self.settings['testFile']
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
        digital_sig = self.get_rsa_signature(sha_hash, rsa_key)
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
        log.info("...  iv: {}".format(encoded_cipher_iv))
        self.send_message("ack")

        # Decode and decrypt key and IV
        log.info("Decoding and decrypting key and iv...")
        cipher_key = base64.b16decode(encoded_cipher_key)
        cipher_iv = base64.b16decode(encoded_cipher_iv)
        rsa_cipher = PKCS1_OAEP.new(rsa_key)
        aes_key = rsa_cipher.decrypt(cipher_key)
        aes_iv = rsa_cipher.decrypt(cipher_iv)
        log.info("... key:\t{}".format(str(aes_key)))
        log.info("...  iv:\t{}".format(str(aes_iv)))

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
            for plain_chunk in iter(lambda: pt_file.read(Sender._BUFFER_SIZE), b''):
                enc_chunk = aes_cipher.encrypt(plain_chunk)
                f.write(enc_chunk)

        # If option is enabled, pause the program to allow modification of encrypted file before transmission
        should_pause = self.settings['pauseBeforeSend'].lower() == 'true'
        if should_pause:
            input("Press return when you are ready to transmit the encrypted signature+message file")

        # Alert receiver that file is ready for transmission and wait for acknowledgment
        self.send_message("Encrypted file is ready to be transmitted")
        self.receive_message()

        # Send encrypted file and wait for ack that it was received
        self.send_file(out_file)
        self.receive_message()

        # Ask and wait for response indicating that file was accepted as unaltered
        self.send_message("Did your computed hash match my digital signature?")
        m = self.receive_message()
        did_match = m == 'true'
        if did_match:
            msg = "\n    __  __     _     _____    ___   _  _ \n   |  \/  |   /_\   |_   _|  / __| | || |\n   | |\/| |  / _ \    | |   | (__  | __ |\n   |_|  |_| /_/ \_\   |_|    \___| |_||_|\n"
        else:
            msg = "\n   ___     ___    ___   ___             \n  / _ \   / _ \  | _ \ / __|            \n | (_) | | (_) | |  _/ \__ \  _   _   _ \n  \___/   \___/  |_|   |___/ (_) (_) (_)\n"

        log.info(msg)



        self.cleanup()



if __name__ == "__main__":
    Sender().main()
