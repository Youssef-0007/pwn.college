from scapy.all import Ether, ARP, sendp

# Construct the ARP reply packet
arp_response = ARP(
    op=2,  # ARP reply
    psrc="10.0.0.42",  # Source IP address
    hwsrc="42:42:42:42:42:42",  # Source MAC address
    pdst="10.0.0.2"  # Destination IP address
)

# Encapsulate in Ethernet frame
ether_frame = Ether(
    dst="ff:ff:ff:ff:ff:ff",  # Broadcast MAC address
    src="42:42:42:42:42:42"  # Source MAC address
)

# Combine Ethernet frame and ARP packet
packet = ether_frame / arp_response

# Send the packet on the network
sendp(packet, verbose=False)

