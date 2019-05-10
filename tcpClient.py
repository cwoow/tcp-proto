import time
import socket
from impacket.ImpactPacket import IP, TCP 

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('127.0.0.1', 1234))
while True:
    client.send(b'hello')
    print('hello')
    time.sleep(1)