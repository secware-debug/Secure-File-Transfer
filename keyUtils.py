from xml.dom import minidom
import logging as log
import settingsParser
from Crypto.PublicKey import RSA

class KeyGenerator():
    def __init__(self) -> None:
        self.settings = settingsParser.parse("config_keyGen.xml", "keyGen_settings", "setting")
        self.init_log()

    def init_log(self):
        d = self.settings
        log.basicConfig(filename=d["logFile"], filemode=d["logMode"], level=int(d["logLevel"]),
                            format=d["logFormat"])

    def generate_rsa_pair(self):
        filename_pub = self.settings["RSAPublicFile"]
        filename_prv = self.settings["RSAPrivateFile"]
        key_size = int(self.settings["RSAKeySize"])

        key = RSA.generate(key_size)
        n = key.key.n    # public modulus component
        e = key.key.e    # public exponent component
        d = key.key.d    # private exponent component

        pub_doc = minidom.Document()

        pub_root = pub_doc.createElement("publicKey")
        pub_root.setAttribute("type", "RSA")
        pub_root.setAttribute("padding", "none")
        pub_doc.appendChild(pub_root)

        pub_key = pub_doc.createElement("key")
        pub_key.setAttribute("n", str(n))
        pub_key.setAttribute("e", str(e))
        pub_root.appendChild(pub_key)

        prv_doc = minidom.Document()

        prv_root = prv_doc.createElement("privateKey")
        prv_key  = prv_doc.createElement("key")
        prv_root.appendChild(prv_key)
        prv_doc.appendChild(prv_root)

        prv_key.setAttribute("n", str(n))
        prv_key.setAttribute("e", str(e))
        prv_key.setAttribute("d", str(d))

        self.__write_xml(pub_doc, filename_pub)
        self.__write_xml(prv_doc, filename_prv)

    def __write_xml(self, document, filename):
        document.writexml(writer=open(file=filename, mode='w', encoding="utf-8"),
                          indent="", addindent="\t", newl="\n", encoding="utf-8")


if __name__ == "__main__":
    kg = KeyGenerator()
    kg.generate_rsa_pair()