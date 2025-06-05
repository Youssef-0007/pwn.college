from pwn import *
from Crypto.Util.number import long_to_bytes

# Fix 1: Use proper bytes for recvuntil
p = process('/challenge/run')

# Fix 2: Match the exact output format (note space after 'd')
p.recvuntil(b'(public)  n = ')
n = int(p.recvline().strip(), 16)
p.recvuntil(b'(public)  e = ')
e = int(p.recvline().strip(), 16)
p.recvuntil(b'(private) d = ')
d = int(p.recvline().strip(), 16)

# Fix 3: Properly handle the ciphertext line
p.recvuntil(b'Flag Ciphertext (hex): ')
ciphertext_hex = p.recvline().strip().decode()

# Convert ciphertext to integer (little-endian as per challenge)
cipher_int = int.from_bytes(bytes.fromhex(ciphertext_hex), 'little')

# Decrypt using RSA
plain_int = pow(cipher_int, d, n)

# Convert to flag (little-endian)
try:
    decrypted_flag = long_to_bytes(plain_int).decode('latin-1')
    flag = decrypted_flag[::-1]
    print(f"Decrypted Flag: {flag}")
except UnicodeDecodeError:
    # Sometimes flags aren't pure text - show hex if decode fails
    print(f"Decrypted Bytes (hex): {long_to_bytes(plain_int).hex()}")
