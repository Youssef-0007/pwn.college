from pwn import *
import hashlib
import os
import re

# Setup pwntools context
context.log_level = 'info'

# Start the process
io = process("/challenge/run")

# Read until we get the prefix line
output = io.recvline().decode()
log.info(f"Received: {output.strip()}")

# Extract the prefix
match = re.search(r"flag_hash\[:prefix_length\]='([0-9a-fA-F]{6})'", output)
if not match:
    log.error("Could not find hash prefix.")
    exit(1)

target_prefix = match.group(1).lower()
log.success(f"Target prefix: {target_prefix}")

# Brute force to find a collision
log.info("Brute-forcing a collision...")
while True:
    candidate = os.urandom(8)
    hash_hex = hashlib.sha256(candidate).hexdigest()
    if hash_hex.startswith(target_prefix):
        log.success(f"Found collision!")
        log.info(f"Data (hex): {candidate.hex()}")
        log.info(f"Hash: {hash_hex}")
        break

# Send the hex of the colliding input
io.sendline(candidate.hex())

# Receive and print the rest of the output
io.interactive()
