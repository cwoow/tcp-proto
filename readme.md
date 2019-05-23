
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
