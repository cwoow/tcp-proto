from rawSocket import RawSocket

server = RawSocket()
server.bind(('127.0.0.1', 1234))
addr = server.accept()
print('connected ...\n ')
while server.isOpen():
    msg = server.recv()
    if msg:
        print(msg)
        server.send(msg)
        print(msg)
print('bye....')