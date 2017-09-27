import socket
import threading
from xml.dom import minidom
import logging
import settingsParser

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
    logging.basicConfig(filename=settings["logFile"], filemode=settings["logMode"], level=int(settings["logLevel"]),
                        format=settings["logFormat"])

    logging.info("Receiver started. Settings loaded")
    logging.debug("Settings:" + str(settings)+'\n')

    # initialize socket
    # socket constructor takes a tuple of (address, port)
    port = int(settings["port"])
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('localhost', port))

    print("Listening on port {:d} for new connections:".format(port))
    sock.listen()
    logging.info("The host is listening for new connections on port {:d}".format(port))

    accept_connections(sock)


def accept_connections(sock : socket):
    socket_id = 1

    while True:
        connection, remote_address = sock.accept()
        msg = "Accepted a new connection from {}:{}".format(remote_address[0], remote_address[1])
        logging.info(msg)
        print(msg)

        receiver = ThreadedReceiver(connection, remote_address, socket_id)
        receiver.start()
        socket_id += 1


class ThreadedReceiver(threading.Thread):
    """
    Inherits from the Thread class which makes setting up multi-threading simple.
    Must override two functions. __init()_ and run(). Run() will be called when Thread.start() is called
    """
    def __init__(self, connection: socket.socket, remote: str, id: int):
        super().__init__()      # chain call to parent constructor
        self.connection = connection
        self.remote_address = remote
        self.connection_id = id

    def run(self):
        logging.info("Thread #{} created and started".format(self.connection_id))
        self.connection.close()



if __name__ == "__main__":
    init()

