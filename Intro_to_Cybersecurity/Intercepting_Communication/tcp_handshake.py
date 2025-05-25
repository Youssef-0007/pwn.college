from scapy.all import *

target_ip = "10.0.0.2"
ip = IP(dst=target_ip)
syn = TCP(sport=31337,dport=31337,flags="S", seq=31337)
syn_ack = sr1(ip/syn, timeout=2)

if syn_ack is None:
	print("No SYN_ACK received. Handshake faild!")
	exit()


ack = TCP(
	sport=31337,
	dport=31337,
	seq=syn_ack.ack,
	ack=syn_ack.seq + 1,
	flags="A"
)

send(ip/ack)
print("Handshake completed.")
