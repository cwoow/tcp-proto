
import json
import math
from functools import partial

import socket

class BufferMap():
    fmt = {}

    def __init__(self, buf=None, size=20):
        self.buf = list(buf) if buf else [0]*size
        for key in self.fmt:
            self.__setattr__('get_'+key, partial(self.get, key))
            self.__setattr__('set_'+key, partial(self.set, key))

    def get_bytes(self):
        return bytes(self.buf)

    def _get(self, byte, start_bit, lest):
        """读取buf指定位置的值
        byte: 起始字节
        start_bit: 起始位
        lest: 位长度
        """
        value = 0
        while lest > 0:
            n = self.buf[byte]
            if lest >= 8-start_bit:
                bit_len = 8-start_bit
            else:
                bit_len = lest 
            end_bit = start_bit + bit_len
            byte_value = n >> (8-end_bit) & (2**bit_len-1)
            value = (value << bit_len) + byte_value

            start_bit = 0
            byte = byte + 1
            lest = lest - bit_len
        return value

    def _set(self, byte, start_bit, lest, value):
        """设置buf指定位置的值
        byte: 起始字节
        start_bit: 起始位
        lest: 位长度
        value: 要设置的值
        """
        while lest > 0:
            if lest >= 8-start_bit:
                bit_len = 8-start_bit
            else:
                bit_len = lest 
            end_bit = start_bit + bit_len

            mask = ( (2**bit_len-1) << (8-end_bit) ) % 256
            n = ( (value >> (lest-bit_len)) << (8-end_bit) ) %256
            self.buf[byte] = self.buf[byte] & (~mask) | n

            start_bit = 0
            byte = byte + 1
            lest = lest - bit_len

    def get(self, key):
        """读取key的值"""
        byte, start_bit, bit_len = self.fmt[key]
        return self._get(byte, start_bit, bit_len)

    def set(self, key, value):
        """设置key的值"""
        byte, start_bit, bit_len = self.fmt[key]
        self._set(byte, start_bit, bit_len, value)

    def getb(self, key):
        """读取key的bytes值"""
        value = self.get(key)
        b = self.itob(value)
        return b
    
    def setb(self, key, b):
        """给key设置bytes值"""
        value = self.btoi(b)
        self.set(key, value)

    def itob(self, n, l=0):
        """int转bytes"""
        h = hex(n)[2:]
        l = l*2 or math.ceil( len(h)/2 )*2
        while len(h) < l:
            h = '0' + h
        return bytes.fromhex(h)

    def btoi(self, b):
        """bytes转int"""
        n = int.from_bytes(b, byteorder='big')
        return n

    def compute_checksum(self, anArray):
        "Return the one's complement of the one's complement sum of all the 16-bit words in 'anArray'"
        nleft = len(anArray)
        sum = 0
        pos = 0
        while nleft > 1:
            sum = anArray[pos] * 256 + (anArray[pos + 1] + sum)
            pos = pos + 2
            nleft = nleft - 2
        if nleft == 1:
            sum = sum + anArray[pos] * 256
        return self.normalize_checksum(sum)

    def normalize_checksum(self, aValue):
        sum = aValue
        sum = (sum >> 16) + (sum & 0xFFFF)
        sum += (sum >> 16)
        sum = (~sum & 0xFFFF)
        return sum

    def __str__(self):
        d = {}
        for key in self.fmt:
            d[key] = self.get(key)
        return json.dumps(d, indent=1)


class IP(BufferMap):
    fmt = {
        "version":  [0, 0, 4],
        "hlen":     [0, 4, 4],
        "sevice":   [1, 0, 8],
        "len":      [2, 0, 2*8],
        "identify": [4, 0, 2*8],
        "flag":     [6, 0, 3],
        "index":    [6, 3, 13],
        "live":     [8, 0, 8],
        "proto":    [9, 0, 8],
        "sum":      [10, 0, 2*8],
        "src":      [12, 0, 4*8],
        "dst":      [16, 0, 4*8],
    }
    def __init__(self, *args, **kws):
        BufferMap.__init__(self)
        self.tcp = None

    def contains(self, tcp):
        self.tcp = tcp

    def set_ip_src(self, ip):
        self.setb('src', socket.inet_aton(ip))

    def get_ip_src(self):
        return socket.inet_ntoa(self.getb('src'))

    def set_ip_dst(self, ip):
        self.setb('dst', socket.inet_aton(ip))

    def get_ip_dst(self):
        return socket.inet_ntoa(self.getb('dst'))

    def get_packet(self):
        if self.get_version() == 0:
            self.set_version(4)
        if self.get_hlen() == 0:
            self.set_hlen(len(self.buf)//4)
        if self.get_len() == 0:
            l = len(self.buf)
            if self.tcp:
                l += len(self.tcp.buf)
            self.set_len(l)
        if self.get_live() == 0:
            self.set_live(255)
        if self.get_proto() == 0 and self.tcp:
            self.set_proto(self.tcp.get_proto())
        
        self.set_sum(0)
        self.set_sum(self.compute_checksum(self.get_bytes()))

        return self.get_bytes()

''' tcp头
源端口 目的端口 序号  确认号       数据偏移     保留 
[0-1] [2-3]  [4-7] [8-11] [12b 0-3      4-7][13b 0-1]

     URG ACK PSH RST SYN FIN  窗口     校验和   紧急指针 选项
[13b 2    3   4   5   6   7 ] [14-15] [16-17] [18-19] [最长40]
'''
class TCP(BufferMap):
    fmt = {
        "src": [0, 0, 2*8],
        "dst": [2, 0, 2*8],
        "seq": [4, 0, 4*8],
        "ack": [8, 0, 4*8],
        "idx": [12, 0, 4],
        "URG": [13, 2, 1],
        "ACK": [13, 3, 1],
        "PSH": [13, 4, 1],
        "RST": [13, 5, 1],
        "SYN": [13, 6, 1],
        "FIN": [13, 7, 1],
        "win": [14, 0, 2*8],
        "sum": [16, 0, 2*8],
        "upt": [18, 0, 2*8],
    }

    def checksum(self, ipbuf):
        self.set('sum', 0)
        buf = ipbuf + bytes(self.buf[0:20])
        sum = 0
        i = 0
        while i < len(buf):
            sum += self.btoi(buf[i:i+2])
            i += 2
        self.set('sum', sum)

if __name__ == '__main__':
    import unittest
    class BufferTest(BufferMap, unittest.TestCase):
        fmt = {
            "a": [0, 0, 4],
            "b": [0, 4, 4],
            "c": [0, 4, 8],
            "d": [1, 0, 4]
        }

        def __init__(self, *args, **kws):
            BufferMap.__init__(self)
            unittest.TestCase.__init__(self, *args, **kws)

        def test_buffer(self):
            self.set_a(0x1)
            self.assertEqual(self.get_a(), 0x1)

            self.set_b(0x3)
            self.set_a(0x11)
            self.assertEqual(self.get_a(), 0x1)
            self.assertEqual(self.get_b(), 0x3)

            self.set_c(0x55)
            self.assertEqual(self.get_a(), 0x1)
            self.assertEqual(self.get_b(), 0x5)
            self.assertEqual(self.get_c(), 0x55)
            self.assertEqual(self.get_d(), 0x5)

            self.setb('c', b'e')
            self.assertEqual(self.getb('c'), b'e')

    from impacket.ImpactPacket import IP as im_IP, TCP as im_TCP
    class IPTest(unittest.TestCase):

        def test_packet(self):
            ip = IP()
            ip.set_ip_src('127.0.0.1')
            ip.set_ip_dst('127.0.0.1')
            im_ip = im_IP()
            im_ip.set_ip_src('127.0.0.1')
            im_ip.set_ip_dst('127.0.0.1')
            self.assertEqual(ip.get_packet(), im_ip.get_packet())

    unittest.main()



    



    

    