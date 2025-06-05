from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

p = process('/challenge/run')

# Extract the key 
p.recvuntil("AES Key (hex): ")
key_hex = p.recvline().strip().decode()
key = bytes.fromhex(key_hex)

# Extract the flag 
p.recvuntil("Flag Ciphertext (hex): ")
ciphertext_hex = p.recvline().strip().decode()
ciphertext = bytes.fromhex(ciphertext_hex)

# Extract IV (first 16 bytes) and actual ciphertext
iv = ciphertext[:16]
encrypted_flag = ciphertext[16:]

# Create cipher and decrypt
cipher = AES.new(key = key, mode=AES.MODE_CBC, iv = iv)
decrypted_padded = cipher.decrypt(encrypted_flag)

# Remove padding 
flag = unpad(decrypted_padded, AES.block_size)

print("Decrypted Flag: ", flag.decode())
