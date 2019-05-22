import time
from rawSocket import RawSocket

client = RawSocket()
client.connect(('127.0.0.1', 1234))

'''
for msg in [b'hello', b'world', b'!']:
    client.send(msg)
    print(msg)
    print(client.recv())
    time.sleep(1)
'''
client.close()