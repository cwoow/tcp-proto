import socket
from impacket.ImpactPacket import IP, TCP 

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('127.0.0.1', 1234))
server.listen()

while True:
    conn, addr = server.accept()
    pass