
import json
import math

class BufferMap():
    def __init__(self, buf=None):
        self.buf = list(buf) if buf else [0]*20

    def get(self, key):
        byte, bit, lest = self.fmt[key]
        value = 0
        while lest > 0:
            n = self.buf[byte]
            if lest >= 8-bit:
                bit_len = 8-bit
            else:
                bit_len = lest 
            end_bit = bit + bit_len
            n = n >> (8-end_bit) 
            n = n & (2**bit_len-1)
            value = (value << bit_len) + n

            bit = 0
            byte = byte + 1
            lest = lest - bit_len
        return value

    def set(self, key, value):
        byte, bit, lest = self.fmt[key]
        while lest > 0:
            if lest >= 8-bit:
                bit_len = 8-bit
            else:
                bit_len = lest 
            end_bit = bit + bit_len

            place = ( (2**bit_len-1) << (8-end_bit) ) % 256
            n = ( (value >> (lest-bit_len)) << (8-end_bit) ) %256
            self.buf[byte] = self.buf[byte] & (~place) | n

            bit = 0
            byte = byte + 1
            lest = lest - bit_len

    @classmethod
    def ntob(self, n, l=0):
        h = hex(n)[2:]
        l = l*2 or math.ceil( len(h)/2 )*2
        while len(h) < l:
            h = '0' + h
        return bytes.fromhex(h)

    @classmethod
    def btoh(self, b):
        n = int.from_bytes(b, byteorder='big')
        return n

    def getb(self, key):
        value = self.get(key)
        b = self.ntob(value)
        return b
    
    def setb(self, key, b):
        n = self.btoh(b)
        self.set(key, n)


    def __str__(self):
        d = {}
        for key in self.fmt:
            d[key] = self.get(key)
        return json.dumps(d, indent=1)


class IPHead(BufferMap):
    fmt = {
        "version": [0, 0, 4],
        "hlen": [0, 4, 4],
        "sevice": [1, 0, 8],
        "len": [2, 0, 2*8],
        "identify": [4, 0, 2*8],
        "flag": [6, 0, 3],
        "index": [6, 3, 13],
        "live": [8, 0, 8],
        "proto": [9, 0, 8],
        "sum": [10, 0, 2*8],
        "src": [12, 0, 4*8],
        "dst": [16, 0, 4*8],
    }

''' tcp头
源端口 目的端口 序号  确认号       数据偏移     保留 
[0-1] [2-3]  [4-7] [8-11] [12b 0-3      4-7][13b 0-1]

     URG ACK PSH RST SYN FIN  窗口     校验和   紧急指针 选项
[13b 2    3   4   5   6   7 ] [14-15] [16-17] [18-19] [最长40]
'''

class TCPHead(BufferMap):
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
            sum += self.btoh(buf[i:i+2])
            i += 2
        self.set('sum', sum)



if __name__ == '__main__':
    a = TCPHead()
    a.set('SYN', 1)
    a.set('ACK', 0)
    print(a)




    

    