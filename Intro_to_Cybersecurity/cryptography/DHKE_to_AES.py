from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

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


p.recvuntil(b'Flag Ciphertext (hex): ')
ciphertext_hex = p.recvline().strip().decode()
ciphertext = bytes.fromhex(ciphertext_hex)

iv = ciphertext[:16]
encrypted_flag = ciphertext[16:]

key = s.to_bytes(256, 'little')[:16]

cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
flag = unpad(cipher.decrypt(encrypted_flag), AES.block_size)

# Get the flag
print(f"Decrypted Flag: {flag.decode()}")

p.close()
