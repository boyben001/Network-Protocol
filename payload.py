import scapy.all as scapy
import time
from scapy import *


clientInfo=[]
def get_mac(ip):
    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst ="ff:ff:ff:ff:ff:ff")
    ippkt = scapy.IP(dst="192.168.1.2",ttl=10)
    tcp = scapy.TCP(sport=8888, dport=80)
    payload="stfu2"
    arp_request_broadcast = broadcast / arp_request/ippkt/tcp/payload
    #arp_request_broadcast.show()
    #print(arp_request_broadcast.payload.layers())
    #rawPayload = (arp_request_broadcast.getlayer(scapy.IP).version)
    #rawPayload = arp_request_broadcast.layers()
    #arp_request_broadcast.getlayer(scapy.packet.Raw).load="stfu3"
    arp_request_broadcast.getlayer(1).hwsrc='5'
    #rawPayload = (arp_request_broadcast.getlayer(layers.l2.Ether).dst)
    #rawPayload = (arp_request_broadcast.getlayer(layers.inet.TCP).sport)
    #print(rawPayload)
    print("1")



    
    
    answered_list = scapy.srp(arp_request_broadcast, timeout = 5, verbose = False)[0]
    arp_request_broadcast.show()
    for i,recieved in answered_list:
        clientInfo.append({'ip':recieved.psrc,'mac':recieved.hwsrc})
        

    return 0

def spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op = 2, pdst = target_ip, 
                     hwdst = get_mac(target_ip), 
                               psrc = spoof_ip)
  
    scapy.send(packet, verbose = False)

#arp_request = scapy.ARP(pdst = ip)
#broadcast = scapy.Ether(dst ="ff:ff:ff:ff:ff:ff")
#arp_request_broadcast = broadcast / arp_request
#answered_list = scapy.srp(arp_request_broadcast, timeout = 5, verbose = False)[0]

ip="192.168.1.0/24"
get_mac(ip)
for iter in clientInfo:
    print(iter['ip']+' || '+iter['mac'])
#print(hwdst)