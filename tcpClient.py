import time
import socket
from impacket.ImpactPacket import IP, TCP 

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('127.0.0.1', 1234))

for msg in [b'hello', b'world', b'!']:
    client.sendall(msg)
    print(msg)
time.sleep(1)