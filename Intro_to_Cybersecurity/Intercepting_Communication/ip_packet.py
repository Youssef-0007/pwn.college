from scapy.all import *

ip_packet = IP(dst="10.0.0.2", proto=0xFF) / Raw(load=b"CustomProtoPayload")

send (ip_packet, verbose=True)
