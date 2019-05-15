
import socket
from impacket.ImpactPacket import IP, TCP 

server = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
server.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
server.bind(('127.0.0.1', 1234))

state = 0
def reply(ip, tcp):
    buf = tcp.get_packet()[:20]
    buf = [n for n in buf]
    buf[12] = 80
    buf = bytes(buf)
    tcp = TCP(buf)

    ip.contains(tcp)
    tcp.swapSourceAndDestination()
    return ip, tcp


while True:
    data, addr = server.recvfrom(4096)
    #print(addr, data)
    ip = IP(data)
    ip_len = ip.get_size()
    tcp = TCP(data[ip_len:])
    if tcp.get_th_dport() == 1234:
        print('state', state)
        #buf = tcp.get_packet()
        #print([hex(n)[2:] for n in buf])
        print(tcp, tcp.get_th_seq(), tcp.get_th_ack())
        if state == 0:
            ip, tcp = reply(ip, tcp)
            tcp.set_th_ack(tcp.get_th_seq()+1)
            tcp.set_th_seq(0)
            #print('###', tcp.get_th_seq())
            tcp.set_ACK()
            tcp.calculate_checksum()
            buf = ip.get_packet()
            print(tcp, tcp.get_th_seq(), tcp.get_th_ack())
            server.sendto(buf, ('127.0.0.1', 0))
            state = 1
        elif state == 1:
            if tcp.get_SYN() or not tcp.get_ACK():
                break
            print('connected...')
            state = 2
        elif state == 2:
            if tcp.get_FIN():
                ip, tcp = reply(ip, tcp)
                tcp.set_th_ack(tcp.get_th_seq()+data_len)
                tcp.set_th_seq(1)
                tcp.reset_FIN()
                buf = ip.get_packet()
                print(tcp, tcp.get_th_seq(), tcp.get_th_ack())
                server.sendto(buf, ('127.0.0.1', 0))
                
                tcp.set_FIN()
                buf = ip.get_packet()
                print(tcp, tcp.get_th_seq(), tcp.get_th_ack())
                server.sendto(buf, ('127.0.0.1', 0))

                state = 3
            else:
                tcp_len = tcp.get_size()
                head_len = (ip_len+tcp_len)
                msg = data[head_len:]
                data_len = len(data) - head_len
                print(msg)
                ip, tcp = reply(ip, tcp)
                tcp.set_ACK()
                tcp.reset_PSH()
                tcp.set_th_ack(tcp.get_th_seq()+data_len)
                tcp.set_th_seq(1)
                tcp.calculate_checksum()
                buf = ip.get_packet()
                print(tcp, tcp.get_th_seq(), tcp.get_th_ack())
                server.sendto(buf, ('127.0.0.1', 0))
        elif state == 3:
            print('closed...')
            break

        print('\n')
