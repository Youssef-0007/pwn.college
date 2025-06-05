from pwn import *
import hashlib
import base64
import os

context.log_level = 'info'

# Start the challenge binary
io = process("/challenge/run")

# Read welcome messages until challenge is shown
lines = []
while True:
    line = io.recvline().decode().strip()
    print(line)
    lines.append(line)
    if line.startswith("challenge (b64):"):
        break

# Extract base64 challenge
b64_data = line.split(":")[1].strip()
challenge = base64.b64decode(b64_data)
log.success(f"Challenge data (decoded): {challenge.hex()}")

# Brute force to find a response
log.info("Brute-forcing response...")
while True:
    response = os.urandom(8)
    combined = challenge + response
    digest = hashlib.sha256(combined).digest()
    if digest.startswith(b"\x00\x00"):
        log.success(f"Found valid response!")
        break

# Send response (base64 encoded)
response_b64 = base64.b64encode(response).decode()
log.info(f"Sending response (b64): {response_b64}")
io.sendline(response_b64)

# Drop to interactive mode to show final output
io.interactive()
