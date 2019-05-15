import time
import socket
from impacket.ImpactPacket import IP, TCP 

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('127.0.0.1', 1234))

for msg in [b'hello', b'world', b'!']:
    client.send(msg)
    print(client.recv(4096))
time.sleep(1)