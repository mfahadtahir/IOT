import socket
from uuid import getnode as get_mac

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 10286        # The port used by the server

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    # data = {
    #     "network": "unotron",
    #     "action":"register",
    #     "mac" : get_mac(),
    # }
    data = {
        "action":"verify",
        "hash": "",
        "body":'{"network": "unotron", "mac" : get_mac(), "certificate": ""}'
    }
    s.sendall(data.to_bytes(50, 'little'))
    data = s.recv(2048)
    print(get_mac())
print('Received', repr(data))
