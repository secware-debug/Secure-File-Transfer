import threading
from socket import *
import re
import os.path

# static values
from datetime import datetime

portNumber = 3349
packetSize = 2**12
serverName = "cs3700a.msudenver.edu"


# helper methods
def get_resource(filename):
    if (filename.startswith('/')):
        filename = '.' + filename

    if (not os.path.isfile(filename)):
        return None

    with open(filename) as myFile:
        return myFile.read()


# threaded HTTP connection
class HttpConnection(threading.Thread):
    def __init__(self, thread_id, connection_socket, remote_address):
        super(HttpConnection, self).__init__()
        self.threadID = thread_id
        self.socket = connection_socket
        self.address = remote_address

    def run(self):

        req_text = ''

        try:
            req_text = self.socket.recv(packetSize)
        except Exception as e:
            print("Null input received. Ending thread {}".format(self.threadID))


        if (req_text is None or req_text == ''):
            print("Null input received. Ending thread {}".format(self.threadID))
            return


        req_text_lines = req_text.splitlines()
        req_line = req_text_lines[0]
        host_line = req_text_lines[1]
        agent_line = req_text_lines[2]

        # identify type of request, filename, and HTTP version using regular expressions
        type_pattern = re.compile("^([A-Z])*")
        filename_pattern = re.compile(r"([\w\/])*(\/){1}(\w)*(.){1}(\w){3,4}")
        http_version_pattern = re.compile(r"(HTTP\/)(\d+.?\d*)")
        user_agent_patern = re.compile(r"(User-Agent: )([\w\d\s]*$)")

        method_type = type_pattern.search(req_line).group(0)
        filename = filename_pattern.search(req_line).group(0)
        http_version = http_version_pattern.search(req_line).group(2)
        user_agent = user_agent_patern.search(agent_line).group(2)


        # construct the response
        version = http_version if (http_version) else "1.1"
        status_code = ""
        status_phrase = ""
        date = datetime.now().strftime("%a, %d %b %Y %H:%M:%S %Z")
        server = serverName

        if (method_type != "GET"):
            status_code = 400
            status_phrase = "Bad Request"
        else:
            if get_resource(filename) is None:
                status_code = 404
                status_phrase = 'Not Found'
            else:
                print("Resource <{}> located".format(filename))
                status_code = 200
                status_phrase = 'OK'

        rsp_stat_line = "HTTP/{} {} {}\r\n".format(version, status_code, status_phrase)
        rsp_date_line = "Date: {}\r\n".format(date)
        rsp_server_line = "Server: {}\r\n".format(server)
        rsp_first_blank_line = '\r\n'
        rsp_body = (get_resource(filename) + ("\r\n" * 4)) if status_code == 200 else ""

        response_header = rsp_stat_line + rsp_date_line + rsp_server_line + rsp_first_blank_line
        response_text = response_header + rsp_body

        print("Processing Request:\n---start---\n{}---end---\n".format(req_text))
        print(
        "EXTRACTED:\n\ttype: {}\n\tfilename: {}\n\thttp version: {}\n\tuser-agent: {}\n".format(method_type, filename,
                                                                                                http_version,
                                                                                                user_agent))
        print("Response Header:\n---start---\n{}---end---\n".format(response_header))

        # send the response
        self.socket.send(response_text)
        print("Response sent")


        # wait for the next request
        self.run()





# create and bind the socket
sock = socket(AF_INET, SOCK_STREAM)
sock.bind(('', portNumber))

# listen for an incoming connection
sock.listen(1)

print("The server is listening on port {}\n".format(portNumber))


connectionId = 1
while True:
    connectionSocket, address = sock.accept()
    newConnection = HttpConnection(connectionId, connectionSocket, address)
    print("Accepted new connection #{}".format(connectionId))
    connectionId += 1
    newConnection.start()


