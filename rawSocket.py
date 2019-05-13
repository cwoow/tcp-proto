
import socket
from impacket.ImpactPacket import IP, TCP 

class RawSocket():
    CLOSED = 0          # 初始状态
    LISTEN = 1          # 服务端监听状态，等待客户端连接
    SYN_SENT = 2        # 客户端发起连接，发送SYN报文
    SYN_RCVD = 3        # 服务端收到SYN，发送SYN-ACK
    ESTABLISHED = 4     # 确认建立连接
    FIN_WAIT_1 = 5      # 主动关闭连接，发送FIN，等待ACk
    FIN_WAIT_2 = 6      # 半关闭连接，收到ACk，等待FIN，只能接收不能发送
    TIME_WAIT = 7       # 收到FIN后等待 2*MSL
    CLOSING = 8         # 双方同时发送FIN
    CLOSE_WAIT = 9      # 已回复FIN-ACK，等待程序处理完后发FIN
    LAST_ACK = 10       # 等待主动关闭端的FIN-ACk

    def __init__(self, family=socket.AF_INET, type=socket.SOCK_RAW, proto=socket.IPPROTO_TCP):
        self.sock = socket.socket(family, type, proto)
        self.sock.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
        self.src_addr = None
        self.dst_addr = None
        self._state = self.CLOSED

    def bind(self, addr):
        self.sock.bind(addr)
        self.src_addr = tuple(addr)
        self._state = self.LISTEN

    def accept(self):
        if self._state != self.CLOSED:
            raise Exception("worng state:", self._state)
        while True:
            ip, tcp, addr = self.recv()
            if self._state == self.LISTEN and tcp.get_SYN():
                self.dst_addr = tuple(addr)
                ack = self.get_th_seq()+1
                self.send(seq=0, ack=ack, SYN=1)
                self._state = self.SYN_RCVD
            if self._state == self.SYN_RCVD and tcp.get_ACK():
                self._state = self.ESTABLISHED
                return addr

    def close(self):
        self.send(ACK=1, FIN=1)
        self._state = self.FIN_WAIT_1
        while True:
            ip, tcp, addr = self.recv()
            break


    def beclose(self):
        ack = self.get_th_seq()
        self.send(ACK=1)
        self._state = self.CLOSE_WAIT
        self.send(ACK=1, FIN=1)
        self._state = self.LAST_ACK
        ip, tcp, addr = self.recv()
        if tcp.get_ACK():
            self._state = self.CLOSED


    def checkFin(func):
        def decorater(self):
            def wraper(*args, **kws):
                ip, tcp, addr = func(*args, **kws)
                if self._state == self.ESTABLISHED and tcp.get_FIN():
                    self.beclose()
                return ip, tcp, addr
            return wraper
        return decorater

    @checkFin
    def recv(self):
        while True:
            data, addr = self.sock.recvfrom(4096)
            if self.dst_addr is not None and self.dst_addr != tuple(addr):
                continue
            ip = IP(data)
            ip_len = ip.get_size()
            tcp = TCP(data[ip_len:])
            return ip, tcp, addr

    def send(self, msg=None, seq=0, ack=0, SYN=0, ACK=0, PSH=0, FIN=0):
        ip, tcp = self.init_head()
        if seq:
            tcp.set_th_seq(seq)
        if ack:
            tcp.set_th_ack(ack)
        if SYN:
            tcp.set_SYN()
        if ACK:
            tcp.set_ACK()
        if PSH:
            tcp.set_PSH()
        if FIN:
            tcp.set_FIN()
        buf = ip.get_packet()
        if msg is not None:
            if isinstance(msg, str):
                msg = msg.encode()
            if not isinstance(msg, bytes):
                raise Exception('msg type error')
            buf += msg
        self.sock.sendto(buf, self.dst_addr)
        
    def init_ip(self):
        ip = IP()
        ip.set_ip_src(self.src_addr[0])
        ip.set_ip_dst(self.dst_addr[0])
        return ip

    def init_tcp(self):
        tcp = TCP()
        tcp.set_th_sport(self.src_addr[1])
        tcp.set_th_dport(self.dst_addr[1])
        return tcp

    def init_head(self):
        ip = self.init_ip()
        tcp = self.init_tcp()
        ip.contains(tcp)
        return ip, tcp

    def swap(self, ip, tcp):
        src_ip = self.ip.get_ip_src()
        dst_ip = self.ip.get_ip_dst()

server = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
server.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
server.bind(('127.0.0.1', 1234))

state = 0
def reply(ip, tcp):
    buf = tcp.get_packet()
    buf = [n for n in buf]
    buf = bytes(buf)
    tcp = TCP(buf)

    ip.contains(tcp)
    tcp.swapSourceAndDestination()
    return ip, tcp


while True:
    data, addr = server.recvfrom(4096)
    #print(addr, data)
    ip = IP(data)
    ip.get_ip_src()
    ip.get_ip_dst()
    
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
