from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def decrypt_aes_ecb():
	# Start the challenge process
	p = process('/challenge/run')

	# Extract the key
	p.recvuntil(b'AES Key (hex): ')
	key_hex = p.recvline().strip().decode()
	key = bytes.fromhex(key_hex)

	# Extract the cipher flag
	p.recvuntil(b'Flag Ciphertext (hex): ')
	ciphertext_hex = p.recvline().strip().decode()
	ciphertext = bytes.fromhex(ciphertext_hex)

	# Calculate number of blocks
	block_size = AES.block_size
	num_blocks = len(ciphertext) // block_size

	# Initialze the ES cipher
	cipher = AES.new(key = key, mode=AES.MODE_ECB)

	# Decrypte each block and build the plaintext of the flag
	flag_plaintext = b''
	for i in range(num_blocks):
		start = i * block_size
		end = start + block_size
		block = ciphertext[start:end]

		decrypted_block = cipher.decrypt(block)
		flag_plaintext += decrypted_block

	try:
		flag_plaintext = unpad(flag_plaintext, block_size)
	except ValueError:
		pritn("Warning: Padding removal failed - may have incorrect key or ciphertext")

	print(f"\nDecrypted flag: {flag_plaintext.decode()}")

	p.close()

if __name__ == '__main__':
	decrypt_aes_ecb()
