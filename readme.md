# Secure TCP file transmission using RSA

Use RSA and AES encryption to encrypt and verify the transmission of a file over a TCP connection.
RSA is used to securely exchange a symmetric AES encryption key, and to sign and verify the SHA256
message digest of the transmitted file.

### **WARNING: DO NOT USE THIS TO TRANSMIT SENSITIVE INFORMATION.**
This module IS NOT designed to be used in any kind of real-world application. Although the underlying
cryptographic operations are based on well-known and presumably secure standards, the module uses these protocols
in a custom manner. This customization almost certainly introduces numerous attack vectors and security holes.

---

There are three main classes to the program: Sender, Receiver, and KeyUtils. There is also a secondary class for parsing
an XML file for configuration and settings data.

### SENDER:
This class is used to establish a connection to a remote host and then securely transmit a file using a combination
of public encryption, symmetric encryption, and hashing. The overall protocol is custom but follows
the basic structure of an HTTPS connection. The chief difference is that there is no support of certificates.

### RECEIVER:
This class is used as a server that will use a combination of public encryption, symmetric encryption, and hashing
to securely accept a file from a remote host from man-in-the-middle or other interception attacks. The overall
protocol is custom, but essentially mirrors the structure of an HTTPS connection.

### KEYUTILS:
Used to create, save, and import RSA and AES keys. It can be run standalone to create a set of
random RSA and AES keys, or used on demand as a library.

### SETTINGSPARSER:
Enables the parsing of an XML file and importing key-value pairs into a dictionary that other classes
in the program can reference.

---

## General process and communication flow

SENDER:
* Establish a remote socket connection
    * Generate a random RSA key pair
    * Send the remote host the public RSA key
    * Wait for the remote host to respond back with a symmetric AES key encrypted with the public RSA cipher
    * Get a file ready to transmit
         * Generate the SHA256 hash of the file and store it as a message digest ("message-dd")
         * Encrypt (digitally sign) the message digest using the RSA private key ("message.ds-msg")
         * Append the file to the digital signature and encrypt them with the AES key ("message.aescipher)
    * Send the encrypted package to the remote host
    * Wait for the remote host to confirm that the signature matches


RECEIVER:
* Create a TCP socket and listen for a remote host
* When a remote host connects, establish a connection and start a new thread
    * Wait for the remote host to send a public RSA key
    * Generate a random symmetric AES cipher
    * Encrypt the AES key with the sender's public key
    * Send the encrypted AES key to the remote host
    * Receive an encrypted package from the remote host and save it to disk (message.aescipher)
    * Read the encrypted file block by block and do the following:
         * Decrypt each block using the AES key
         * The first 256 bytes contain the digital signature. Save this to memory
         * The rest of the blocks contain the binary data. For each of these blocks
              * Append them to a file ("decrypt_X")
              * Update a SHA256 message digest
    * After the file has been read and decrypted:
         * Write the SHA256 hash value to disk (message.dd)
         * Use the calculated message digest and RSA public key to verify the digital signature
         * Send the remote host a message stating if the verification was successful

---
         
CONFIGURATION:
Configuration information and settings are stored in XML files. Socket addresses, file name and storage locations,
packet and buffer sizes, log formats, etc can be customized by editing the XML document. Note: Some settings such
as the modes for AES and RSA encryption are for information purposes only. Changing them will not affect the
behavior of the program.


LOG FILES:
All communication and internal messages are stored in log files. There is no console output. In addition to process
information, the log files will contain the message digests and digital signatures. The log files also contain both
the raw binary data and base16 encoded values for the AES symmetric key and the corresponding IV. Since the AES key
is chosen at random for each transfer, publishing the information in the log is not a strong security risk.

---

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
Python implementation of AES encryption and SHA hashing is not as efficient as it would be in a lower level language
such as C or C++. As such, the time involved for cryptographic operations on larger files can be long.
During tests, the process took around 5 minutes to complete on a 1GB video file.


LICENSE:
Fully open. You can use, modify, and distribute this software without any restriction, implied or otherwise
"""