import socket
from uuid import getnode as get_mac

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 10286        # The port used by the server

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(b'i am known $$')
    data = s.recv(2048)
    print(mac)
print('Received', repr(data))
