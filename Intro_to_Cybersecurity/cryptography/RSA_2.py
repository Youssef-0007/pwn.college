from pwn import *
from Crypto.Util.number import long_to_bytes, inverse

proc = process('/challenge/run')

# Fix 2: Match the exact output format (note space after 'd')
proc.recvuntil(b'e = ')
e = int(proc.recvline().strip(), 16)
proc.recvuntil(b'p = ')
p = int(proc.recvline().strip(), 16)
proc.recvuntil(b'q = ')
q = int(proc.recvline().strip(), 16)

# compute modulus n
n = p * q

# compute Euler's totient
phi = (p - 1) * (q - 1)

# compute private exponent d
d = inverse(e, phi)

# Fix 3: Properly handle the ciphertext line
proc.recvuntil(b'Flag Ciphertext (hex): ')
ciphertext_hex = proc.recvline().strip().decode()

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
