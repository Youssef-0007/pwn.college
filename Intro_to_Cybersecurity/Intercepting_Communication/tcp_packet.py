from scapy.all import *

tcp_flags = "APRSF"


packet = IP(dst="10.0.0.2")/ TCP(
	sport=31337,
	dport=31337,
	seq=31337,
	ack=31337,
	flags=tcp_flags
)

send(packet, verbose=True)
