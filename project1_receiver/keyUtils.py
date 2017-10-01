import binascii
import copy
import logging as log
import os
import xml.etree.ElementTree as ET
from xml.dom import minidom

import Crypto.Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

from project1_settingsParser import settingsParser

"""
The KeyUtils class is used to generate both RSA key paris and AES symmetric keys. The class has methods for generating
keys, saving them as XML files, and importing keys from XML files.

The general format for the XML file is
<type type="enc_type" attrib2="xxx" ... attribN="xxx">
    <key keySize="n" binaryEncoding="xxx">value</keySize>
</type>
"""


# noinspection PyProtectedMember
class KeyUtils():
    def __init__(self) -> None:
        self.settings = settingsParser.parse("config_keyUtils.xml", "keyGen_settings", "setting")
        self.__init_log()

    def __init_log(self) -> None:
        d = self.settings
        log.basicConfig(filename=d["logFile"], filemode=d["logMode"], level=int(d["logLevel"]),
                        format=d["logFormat"])

    @staticmethod
    def __write_xml(node: ET.Element, filename: str) -> None:
        """
        Uses XML.minidom to produce a nicely formatted XML file
        :param node the root element node that is to be written.:
        :param filename path to the output file.:
        :return:
        """
        document = minidom.parseString(ET.tostring(node, 'utf-8'))
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        document.writexml(writer=open(file=filename, mode='w', encoding="utf-8"),
                          indent="", addindent="\t", newl="\n", encoding="utf-8")

    def generate_rsa_key_pair(self) -> RSA._RSAobj:
        """
        Generates an RSA object that can be used for encryption and decryption
        :return An RSA key containing both private and public information:
        """
        key_size = int(self.settings["RSAKeySize"])
        key = RSA.generate(key_size)

        return key

    def write_rsa_keys_to_file(self, key: RSA._RSAobj) -> None:
        """
        Generates an XML file for either a public or private key. Type of file is determined by the presence
        or absence of a the 'd' component/tag.
        :param key: An RSA key:
        :return:
        """
        filename_pub = self.settings["RSAPublicFile"]
        filename_prv = self.settings["RSAPrivateFile"]

        n = key.key.n    # public modulus component
        e = key.key.e    # public exponent component
        d = key.key.d    # private exponent component

        key_type = "RSA"
        padding = "none"
        key_size = str(key.size() + 1)

        root_pub = ET.Element('RSA')
        root_pub.set("type", key_type)
        root_pub.set("padding", padding)

        node_pub = ET.Element("key")
        node_pub.set("keySize", key_size)
        node_pub.set("binaryEncoding", 'none')

        root_prv = copy.deepcopy(root_pub)
        node_prv = copy.deepcopy(node_pub)

        node_n = ET.Element("n")
        node_n.text = str(n)

        node_e = ET.Element("e")
        node_e.text = str(e)

        node_d = ET.Element("d")
        node_d.text = str(d)

        node_pub.append(node_n)
        node_pub.append(node_e)

        node_prv.append(node_n)
        node_prv.append(node_e)
        node_prv.append(node_d)

        root_pub.append(node_pub)
        root_prv.append(node_prv)

        self.__write_xml(root_pub, filename_pub)
        self.__write_xml(root_prv, filename_prv)

    @staticmethod
    def __import_rsa_key_from_node(node: ET.Element) -> RSA._RSAobj:
        """
        Generates a new RSA key object from an XML node
        :param node: the root XML node. Should be of type <RSA>:
        :return: an RSA key object:
        """
        keynode = node.find("key")  # type: ET.Element

        n = int(keynode.find('n').text)
        e = int(keynode.find("e").text)

        d_node = keynode.find('d')

        d = int(d_node.text) if (d_node is not None) else None

        if d:
            return RSA.construct((n, e, d))
        else:
            return RSA.construct((n, e))

    def import_key_from_file(self, filename: str):
        """
        Create a key object from an XML file
        :param filename: path to an XML file with key information:
        :return: a key object corresponding to one of the encryption keys in the pycrypto library:
        """
        tree = ET.parse(filename)
        root = tree.getroot()  # type: ET.Element
        elem_type = root.get("type")
        if elem_type == "AES":
            return self.__import_aes_key_from_node(root)
        elif elem_type == "RSA":
            return self.__import_rsa_key_from_node(root)

    def generate_random_AES_key(self) -> (AES.AESCipher, list, list):
        """
        Creates a random 256 bit key and uses it to generate a new AES encryption object
        :return: a tuple containing the AESCipher, the AES key as a byte string, and the AES IV as a byte string:
        """
        key_size = int(int(self.settings["AESKeySize"]) / 8)
        block_size = 16

        # generate random 256 bit key
        key_val = Crypto.Random.get_random_bytes(key_size)

        # generate random IV
        iv = Crypto.Random.get_random_bytes(block_size)

        # generate key object
        key = AES.new(key=key_val, mode=AES.MODE_CFB, IV=iv, segment_size=8)

        return key, key_val, iv

    def write_AES_key_to_file(self, key_val: bytes, iv: bytes) -> None:
        """
        Creates an XML file with all of the necessary information for a symetric AES key
        :param key_val: A 256 bit bytes string that contains the AES key:
        :param iv: A 32 bit bytes string that contains the AES IV:
        :return:
        """
        settings = self.settings

        outfile = settings["AESFile"]
        type = "AES"
        key_size = settings["AESKeySize"]
        mode = AES.MODE_CFB
        padding = "none"
        segment_size = 8
        binary_encoding = "base64"

        encoded_key = binascii.b2a_base64(key_val).decode("utf-8").replace('\n', '')
        encoded_iv = binascii.b2a_base64(iv).decode("utf-8").replace('\n', '')

        root = ET.Element("AES")
        root.set("type", type)
        root.set("mode", str(mode))
        root.set("padding", padding)
        root.set("segmentSize", str(segment_size))

        key_tag = ET.SubElement(root, "key")  # type: ET.Element
        key_tag.set("keySize", key_size)
        key_tag.set("binaryEncoding", binary_encoding)
        key_tag.text = encoded_key

        iv_tag = ET.SubElement(root, "IV")
        iv_tag.set('binaryEncoding', binary_encoding)
        iv_tag.text = encoded_iv

        self.__write_xml(root, outfile)

    def __import_aes_key_from_node(self, node: ET.Element) -> AES.AESCipher:
        """
        Reads data from an ElementTree Element and uses it to create a new AESCipher
        :param node: The XML node containing key information:
        :return: An AESCipher object
        """
        encoded_key = node.find("key").text
        encoded_iv = node.find("IV").text
        mode = int(node.get("mode"))
        segment_size = int(node.get("segmentSize"))

        decoded_key = binascii.a2b_base64(encoded_key)
        decoded_iv = binascii.a2b_base64(encoded_iv)

        return AES.new(key=decoded_key, mode=mode, IV=decoded_iv, segment_size=segment_size)



if __name__ == "__main__":
    plaintext = "abc123".encode("utf-8")
    kg = KeyUtils()

    # generate RSA key (contains both public and private data)
    rsa_key = kg.generate_rsa_key_pair()

    # export RSA key to xml file
    kg.write_rsa_keys_to_file(rsa_key)

    # encrypt some sample text
    cyphertext_rsa = rsa_key.encrypt(plaintext, 0)

    # import XML files and generate new RSA keys
    pubKey = kg.import_key_from_file(kg.settings["RSAPublicFile"])
    prvKey = kg.import_key_from_file(kg.settings["RSAPrivateFile"])

    # decrypt and print the sample text
    plaintext2 = prvKey.decrypt(cyphertext_rsa)
    print(str(plaintext2, 'utf-8'))

    # generate a random AES key and get the key and IV byte data
    aes_key, key_arr, iv_arr = kg.generate_random_AES_key()

    # use AES to encrypt some sample text
    cyphertext_aes = aes_key.encrypt(plaintext)

    # export the AES key to an XML file
    kg.write_AES_key_to_file(key_arr, iv_arr)

    # import an XML file and create a new AES key
    aesKey = kg.import_key_from_file(kg.settings["AESFile"])

    # decrypt and print the text
    plaintext_aes = aesKey.decrypt(cyphertext_aes)
    print(str(plaintext_aes, 'utf=8'))

