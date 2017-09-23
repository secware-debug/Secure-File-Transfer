import sys
sys.path.append("..")
sys.path.append("..\\Common")

from socket import *
import re
from datetime import datetime

#set up statics
remote_port = 3349
rcv_buffer = 2 ** 16

def run():
    initialization()

    # get input and create connection
    usr_server = get_server()
    time_create_connection = datetime.now().microsecond
    socket = create_connection(usr_server, remote_port)

    # connection established
    time_connection_established = datetime.now().microsecond
    time_delta = (time_connection_established - time_create_connection) / 1000
    print("Socket created. TCP connection was established in {} milliseconds".format(time_delta))

    keep_going = True
    while (keep_going):
        # get user input and construct the http request
        http_req, requested_file = construct_http_request(usr_server)
        print("\r\nGenerating request...")
        print("HTTP Request: \n\n---start---\n{}---end---\r\n".format(http_req))

        # send the request and store the response
        time_send_request = datetime.now().microsecond
        socket.send(http_req)

        response = socket.recv(rcv_buffer)
        time_rcv_response = datetime.now().microsecond
        time_delta = (time_rcv_response - time_send_request) / 1000
        print("Received a response from server {}ms after request was sent\r\n".format(time_delta))

        # process the response
        process_response(response, requested_file)

        print("")

        # Prompt to continue
        keep_going = prompt_continue()

    socket.close()
    exit(0)


def initialization():
    print("Client Program Started\n")

def get_server():
    usr_server = raw_input("Enter address of remote server: ")
    # usr_server = "127.0.0.1"
    return usr_server

def create_connection(server, port):
    print("Creating connection...")
    sock = socket(AF_INET, SOCK_STREAM)
    try:
        sock.connect((server, port))
        return sock
    except Exception as e:
        print(str(e))
        exit(-1)


def construct_http_request(server):
    usr_method_type = raw_input("Enter the HTTP method type: ")
    usr_filename = raw_input("Enter the name of the HTML file: ")
    usr_version = raw_input("Enter the HTTP version: ")
    usr_user_agent = raw_input("Enter your User-Agent Type: ")

    # usr_method_type = "GET"
    # usr_filename = "CS3700.htm"
    # usr_version = "1.2"
    # usr_user_agent = "Firefox"

    # construct the HTTP request object
    req_line = "{} /{} HTTP/{}\r\n".format(usr_method_type, usr_filename, usr_version)
    host_line = "Host: {}\r\n".format(server)
    agent_line = "User-Agent: {}\r\n".format(usr_user_agent)
    blank_line = "\r\n"

    http_req_string = req_line + host_line + agent_line + blank_line
    return http_req_string, usr_filename


def process_response(response_text, requested_file):
    if (response_text is None):
        print("ERROR: The server did not send a response")
        exit(-1)

    response_text = response_text + ""
    lines = response_text.splitlines()
    status_code_pattern = re.compile(r"( )(\d+)( )")
    status_code = status_code_pattern.search(lines[0]).group(2)

    if (status_code != '200'):
        header = response_text
        print("HTTP Response Header:\n\n---start---\r\n{}---end---\r\n".format(header))
    else:
        header, data = get_header_and_data(lines)
        print("HTTP Response Header:\r\n---start---\r\n{}\r\n---end---\r\n".format(header))
        create_file(data, requested_file)



def create_file(file_data, file_name):
    file_data = file_data + " "
    s = "" + file_data

    if file_name.startswith('/'):
        file_name = '.' + file_name

    lines = file_data.splitlines()

    print("Processing data section...")
    for i in range(0, len(lines)):
        found = False
        if lines[i] == "":
            found = True
            for j in range(1, 4):
                if ((i + j) >= len(lines)) or (lines[i + j] != "" and lines[i + j] != " "):
                    found = False
                    break
        if found:
            print("Detected 4-line escape sequence starting with line {}".format(i+1))
            file_data = "\n".join(lines[0:i])
            with open(file_name, 'w') as myFile:
                myFile.write(file_data)
            print("File <{}> written to disk".format(file_name))
            break








def get_header_and_data(lines):
    count = 0
    for line in lines:
        if line == '':
            break
        else:
            count += 1
    return ('\r\n'.join(lines[0:count]), '\r\n'.join(lines[count + 1:]))

def prompt_continue():
    response = raw_input("Do you want to send another request? ")
    if (response.lower() == 'y' or response.lower() == 'yes'):
        return True
    return False


run()