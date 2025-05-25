import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 31337))

response, addr = sock.recvfrom(4096)

print(f"received from {addr}: {response.decode()}")
