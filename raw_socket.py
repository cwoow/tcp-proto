#!/usr/bin python3
# -*- coding: utf-8 -*-
"""raw socket"""
import time
import socket

#from impacket.ImpactPacket import IP, TCP, Data
from socketHead import IP, TCP, Data

class RawSocket:
    """raw socket"""
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

    def __init__(self, family=socket.AF_INET, typ=socket.SOCK_RAW, proto=socket.IPPROTO_TCP):
        self.sock = socket.socket(family, typ, proto)
        self.sock.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
        self.src_addr = None
        self.dst_addr = None
        self._state = self.CLOSED
        self._seq = 0
        self._ack = 0

    def isopen(self):
        """是否连接状态"""
        return self._state == self.ESTABLISHED

    def bind(self, addr=None):
        """绑定端口"""
        if addr:
            self.sock.bind(addr)
            self.src_addr = tuple(addr)
            self._state = self.LISTEN
        else:
            self.sock.bind(('127.0.0.1', 0)) # bind端口0，系统会自动分配一个端口
            self.src_addr = self.sock.getsockname()


    def accept(self):
        """等待客户端连接, 三次握手"""
        if self._state != self.LISTEN:
            raise Exception("worng state:", self._state)
        while True:
            ip, tcp, addr, data = self._recv()
            if self._state == self.LISTEN and tcp.get_SYN():    # 开始握手
                self.dst_addr = tuple(addr)
                self._ack = tcp.get_seq()+1  # 消耗一个ack
                self._send(SYN=1, ACK=1)
                self._seq += 1  # 消耗一个seq
                self._state = self.SYN_RCVD
            if self._state == self.SYN_RCVD and tcp.get_ACK() \
                    and tcp.get_seq() == self._ack:  # 连接成功
                self._state = self.ESTABLISHED
                return addr

    def connect(self, dst_addr):
        """连接到服务器"""
        self.bind()
        if self._state != self.CLOSED:
            raise Exception("worng state:", self._state)
        self.dst_addr = dst_addr
        self._send(SYN=1) # 发起连接
        self._state = self.SYN_SENT
        while True:
            ip, tcp, addr, data = self._recv()
            if self._state == self.SYN_SENT and tcp.get_SYN() and tcp.get_ACK():
                self._seq += 1
                self._ack = tcp.get_seq() + 1
                self._send(ACK=1)
                self._state = self.ESTABLISHED
                return

    def close(self):
        """主动断开连接"""
        self._send(ACK=1, FIN=1)
        self._state = self.FIN_WAIT_1
        while True:
            ip, tcp, addr, data = self._recv()
            if self._state == self.FIN_WAIT_1 and tcp.get_ACK():
                self._state = self.FIN_WAIT_2
            if self._state in [self.FIN_WAIT_1, self.FIN_WAIT_2] and tcp.get_FIN():
                self._ack = tcp.get_seq() + 1
                self._send(ACK=1)
                self._state = self.TIME_WAIT
                time.sleep(1)
                self._state = self.CLOSED
                print("closed...")
                return

    def beclose(self, ip, tcp, addr, data):
        """被动断开连接"""
        ack = tcp.get_seq()
        self._send(ACK=1)
        self._state = self.CLOSE_WAIT
        self._send(ACK=1, FIN=1)
        self._state = self.LAST_ACK
        while True:
            ip, tcp, addr, data = self._recv()
            if tcp.get_ACK():
                self._state = self.CLOSED
                print("closed...")
                #raise Exception('closed!')
                return

    def recv(self):
        """tcp接收数据"""
        msg = b''
        while True:
            if not self._state == self.ESTABLISHED:
                #raise Exception('disconnected', self._state)
                print('disconnected...')
                return b''
            ip, tcp, addr, data = self._recv()
            #print(data, len(data))
            ip_len = ip.get_header_size()
            tcp_len = tcp.get_header_size()
            head_len = (ip_len+tcp_len)
            msg += data[head_len:]
            data_len = len(data) - head_len
            #print(msg)
            self._ack = tcp.get_seq() + data_len
            self._send(ACK=1)
            if tcp.get_PSH():
                break
        return msg

    def send(self, msg):
        """tcp发送数据"""
        if msg is not None:
            if isinstance(msg, str):
                msg = msg.encode()
            if not isinstance(msg, bytes):
                raise Exception('msg type error')
            while True:
                self._send(msg, ACK=1, PSH=1)
                ip, tcp, addr, data = self._recv()
                if tcp.get_ACK() and tcp.get_ack() == self._seq+len(msg):
                    break
                else:
                    time.sleep(1)
            self._seq += len(msg)

    def watchon(func):
        """修饰器，检查连接状态"""
        def wraper(self, *args, **kws):
            ip, tcp, addr, data = func(self, *args, **kws)
            if self._state == self.ESTABLISHED and tcp.get_FIN():
                self.beclose(ip, tcp, addr, data)
            #print(addr, tcp)
            return ip, tcp, addr, data
        return wraper

    @watchon
    def _recv(self):
        """socket接收数据"""
        while True:
            data, addr = self.sock.recvfrom(4096)
            ip = IP(data)
            ip_len = ip.get_header_size()
            tcp = TCP(data[ip_len:])
            if tcp.get_dst() != self.src_addr[1]:
                continue
            addr = (ip.get_ip_src(), tcp.get_src())
            if self.dst_addr is not None and self.dst_addr != tuple(addr):
                continue
            print('recv ', tcp, tcp.get_seq(), tcp.get_ack())
            return ip, tcp, addr, data

    def _send(self, msg=None, win=10, SYN=0, ACK=0, PSH=0, FIN=0):
        """socket发送数据"""
        ip, tcp = self.init_head()
        tcp.set_win(win)   #这个很重要
        tcp.set_seq(self._seq)
        tcp.set_ack(self._ack)
        if SYN:
            tcp.set_SYN(1)
        if ACK:
            tcp.set_ACK(1)
        if PSH:
            tcp.set_PSH(1)
        if FIN:
            tcp.set_FIN(1)
        if msg is not None:
            data = Data(msg)
            tcp.contains(data)
        buf = ip.get_packet()
        print("send ", tcp, tcp.get_seq(), tcp.get_ack())
        self.sock.sendto(buf, self.dst_addr)

    def init_ip(self):
        """初始化ip头"""
        ip = IP()
        ip.set_ip_src(self.src_addr[0])
        ip.set_ip_dst(self.dst_addr[0])
        return ip

    def init_tcp(self):
        """初始化tcp头"""
        tcp = TCP()
        tcp.set_src(self.src_addr[1])
        tcp.set_dst(self.dst_addr[1])
        return tcp

    def init_head(self):
        """初始化头"""
        ip = self.init_ip()
        tcp = self.init_tcp()
        ip.contains(tcp)
        return ip, tcp

if __name__ == '__main__':
    '''server
    server = RawSocket()
    server.bind(('127.0.0.1', 1234))
    addr = server.accept()
    print('connected ...\n ')
    while server.isopen():
        msg = server.recv()
        if msg:
            print(msg)
            server.send(msg)
            print(msg)
    print('bye....')
    '''
    client = RawSocket()
    client.connect(('127.0.0.1', 1234))
    #'''
