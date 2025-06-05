from pwn import *

# Assuming the challenge is running locally or remotely
# Here's how you'd interact with it programmatically

# Run the challenge
p = process('/challenge/run')

# Receive p, g, A
p.recvuntil(b'p = ')
p_val = int(p.recvline().strip(), 16)
p.recvuntil(b'g = ')
g_val = int(p.recvline().strip(), 16)
p.recvuntil(b'A = ')
A_val = int(p.recvline().strip(), 16)

# Compute B and s
k = 1025
B = pow(g_val, k)
s = pow(A_val, k, p_val)

# Send B and s
p.sendline(hex(B)[2:].encode())
p.sendline(hex(s)[2:].encode())

# Get the flag
print(p.recvall().decode())
