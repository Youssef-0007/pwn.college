from pwn import *

# Just generate the payload without running
payload	= b'REPEAT'
payload += b'A' * 99

print("Payload bytes (hex):", payload.hex())
print("Payload length:", len(payload))

# Save to file for GDB input
with open('payload.bin', 'wb') as f:
    f.write(payload)

print("Payload saved to payload.bin")
