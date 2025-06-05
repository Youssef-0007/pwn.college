from Crypto.Util.number import getPrime, inverse, long_to_bytes, bytes_to_long
from base64 import b64decode
from pwn import *

# Step 1: Generate a valid RSA key
e = 65537
while True:
    p = getPrime(512)
    q = getPrime(512)
    n = p * q
    if 2**512 < n < 2**1024:
        phi = (p - 1) * (q - 1)
        try:
            d = inverse(e, phi)
            break
        except ValueError:
            continue

# Step 2: Connect to the challenge
io = process("/challenge/run")

# Step 3: Send e and n
io.sendlineafter(b"e: ", hex(e)[2:])
io.sendlineafter(b"n: ", hex(n)[2:])

# Step 4: Receive the challenge
io.recvuntil(b"challenge: ")
challenge = int(io.recvline().strip(), 16)

# Step 5: Sign it (response = challenge^d mod n)
response = pow(challenge, d, n)
io.sendlineafter(b"response: ", hex(response)[2:])

# Step 6: Receive ciphertext
io.recvuntil(b"secret ciphertext (b64): ")
cipher_b64 = io.recvline().strip().decode()
cipher_bytes = b64decode(cipher_b64)
cipher_int = int.from_bytes(cipher_bytes, "little")

# Step 7: Decrypt it
plain_int = pow(cipher_int, d, n)
plain_bytes = long_to_bytes(plain_int)

# Step 8: Print flag
print("Decrypted flag:", plain_bytes[::-1])
