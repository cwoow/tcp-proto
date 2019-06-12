
* tcpdump 侦听tcp包，类似wireshark
    * sudo tcpdump '(tcp[13] & 4 = 0) and (port 1234)' -i lo
    * sudo tcpdump tcp port 1234 -i lo

* iptables 防火墙工具，过滤数据包
* 过滤RST包  
    * sudo iptables -I INPUT -p tcp --tcp-flags SYN,FIN,RST,URG,PSH RST -j DROP
    * iptables -A OUTPUT -p tcp -dport 50000 --tcp-flags RST RST -j DROP
    -I 插入(insert)规则 -A 添加(append)规则 -D 删除(delete)规则

* 收到 seq=3425881730、2852968954 相当于 seq=0 ?

* wireshark
    * tcp.port == 1234 && tcp.flags.reset==0

* tcpServer 断开连接的时候没有马上发FIN-ACK，

## 函数 socket(family, type, proto)
* family 协议族
    . AF_INET、AF_INET6、AF_LOCAL(AF_UNIX)、AF_ROUTE
* type socket类型
    . SOCK_STREAM、SOCK_DGRAM、SOCK_RAW、SOCK_PACKET、SOCK_SEQPACKET等
    . 内核为我们提供的服务抽象，比如我们要一个字节流
    . SOCK_RAW要管理员权限运行
* proto 协议
    . IPPROTO_TCP、IPPTOTO_UDP、IPPROTO_SCTP、IPPROTO_TIPC等
    . 指定传输协议，要与type搭配
    . IPPROTO_IP = 0 自动选择
* socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
    . 原始ip数据包，发送端填入tcp头，接收端返回数据保护ip头和tcp头
