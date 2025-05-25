from scapy.all import Ether, sendp, get_if_hwaddr, get_if_list

iface = "eth0"  # change this to your actual interface
dst_mac = "8e:87:6b:6f:7e:c8"  # MAC of 10.0.0.2

# Create Ethernet frame with EtherType = 0xFFFF
pkt = Ether(dst=dst_mac, src=get_if_hwaddr(iface), type=0xFFFF) / b"TestPayload"

# Send the packet
sendp(pkt, iface=iface, verbose=True)
