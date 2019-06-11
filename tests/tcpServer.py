import socket
from impacket.ImpactPacket import IP, TCP 

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('127.0.0.1', 1234))
server.listen()

while True:
    print('###')
    print(dir(server))
    conn, addr = server.accept()
    print(dir(server))
    print("new connection:", addr)
    while True:
        data = conn.recv(4096)
        print(data)
        if not data:
            break
        conn.send(data)