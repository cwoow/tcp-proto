
import socket
from impacket.ImpactPacket import IP, TCP 

server = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
server.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
server.bind(('127.0.0.1', 1234))

state = 0
def ack(ip, tcp):
    buf = tcp.get_packet()[:20]
    buf = [n for n in buf]
    buf[12] = 80
    buf = bytes(buf)
    tcp = TCP(buf)

    ip.contains(tcp)
    tcp.swapSourceAndDestination()
    tcp.set_ACK()
    tcp.set_th_ack(tcp.get_th_seq()+1)
    tcp.set_th_seq(1234)
    tcp.calculate_checksum()
    buf = ip.get_packet()

    print(tcp)
    server.sendto(buf, ('127.0.0.1', 0))


while True:
    data, addr = server.recvfrom(4096)
    #print(addr, data)
    ip = IP(data)
    ip_len = ip.get_size()
    tcp = TCP(data[ip_len:])
    if tcp.get_th_dport() == 1234:
        print(tcp)
        if state == 0:
            ack(ip, tcp)
            state = 1
        elif state == 1:
            if tcp.get_SYN() or not tcp.get_ACK():
                break
            state = 2
        else:
            tcp_len = tcp.get_size()
            head_len = (ip_len+tcp_len)
            msg = data[head_len:]
            print(msg)
