import socket

server_ip = "10.0.0.2"
server_port = 31337
client_port = 31338
message = b"Hello, World!\n"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", client_port))
sock.sendto(message, (server_ip, server_port))

response, addr = sock.recvfrom(1024)
print(f"received from {addr}: {response.decode()}")
