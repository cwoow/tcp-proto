
from impacket.ImpactPacket import IP, TCP 

class Check():
    def __init__(self):
        pass

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

a = b'E\x00\x00(\x00\x00\x00\x00\xff\x06\xbd\xcd\x7f\x00\x00\x01\x7f\x00\x00\x01\x04\xd2\xa4b\x00\x00\x00\x01,\n\xed\x18P\x18\xaa\xaaD\xc7\x00\x00hello'
b = a[20:40]
print(len(b), b)
c = [n for n in b]
c[16] = 0
c[17] = 0
print([hex(n)[2:] for n in c])
sum = Check().compute_checksum(c)
print(sum)
print(hex(sum))

    