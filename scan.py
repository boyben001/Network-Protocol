import scapy.all as scapy
import argparse



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
               
      
        
gateway_ip = "192.168.146.236/24"   
scan_result = scan(gateway_ip)    #可拿到所有子網路的封包回應
print_result(scan_result)