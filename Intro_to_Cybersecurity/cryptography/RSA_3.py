from pwn import *
import re
from Crypto.Util.number import *

io = process('/challenge/run')

# Read lines until you get the key values
while True:
    line = io.recvline().decode().strip()
    print(line)  # Optional: helpful for debugging
    if line.startswith("e:"):
        e = int(line.split(":")[1].strip(), 16)
    elif line.startswith("d:"):
        d = int(line.split(":")[1].strip(), 16)
    elif line.startswith("n:"):
        n = int(line.split(":")[1].strip(), 16)
    elif line.startswith("challenge:"):
        challenge = int(line.split(":")[1].strip(), 16)
        break

# Decrypt the challenge using RSA
response_int = pow(challenge, d, n)
response_bytes = long_to_bytes(response_int)
response_hex = response_bytes.hex()

# Send response back
io.sendline(response_hex.encode())

# Receive the final result (flag?)
print(io.recvall().decode())
