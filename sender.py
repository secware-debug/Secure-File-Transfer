import logging as log
import socket
from xml.dom import minidom

class Sender:
    def __init__(self):
        self.settings = {}
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
        doc = minidom.parse(file)
        setting_elements = doc.getElementsByTagName("sender_settings")[0].getElementsByTagName("setting")
        for elm in setting_elements:
            self.settings.update(elm.attributes.items())


    def create_connection(self) -> socket.socket:
        addr = self.settings["remote"]
        port = int(self.settings["port"])

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            sock.connect((addr, port))
            log.info("Connected to {:s}:{:d}".format(addr, port))
            return sock
        except Exception as e:
            log.error(e)



if __name__ == "__main__":
    s = Sender()
    s.init()
    