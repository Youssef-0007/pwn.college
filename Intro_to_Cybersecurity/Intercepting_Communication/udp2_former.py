from scapy.all import *

packet = IP(src="10.0.0.3", dst="10.0.0.2") / UDP(sport=31337, dport=31338) / b"FLAG:10.0.0.1:31337"

send(packet)
