import scapy.all as scapy
import time

ip="192.168.62.0/24"
clientInfo=[]
def get_mac(ip):
    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst ="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout = 5, verbose = False)[0]
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


get_mac(ip)
for iter in clientInfo:
    print(iter['ip']+' || '+iter['mac'])
#print(hwdst)