# Many-time pad 

from pwn import *
from Crypto.Util.strxor import strxor

def main():
	p = process('/challenge/run')

	# Get the encrypted flag
	p.recvuntil(b'Flag Ciphertext (hex): ')
	flag_ct = bytes.fromhex(p.recvline().strip().decode())

	# Send null bytes to get the key
	null_plain = b'\x00' * len(flag_ct)
	p.sendlineafter(b'Plaintext (hex): ', null_plain.hex().encode())
	p.recvuntil(b'Ciphertext (hex): ')
	null_ct = bytes.fromhex(p.recvline().strip().decode())
	print(f"[DEBUG] cipher null:", null_ct)
	key = strxor(null_plain, null_ct)
	print(f"[DEBUG] key:", key)
	flag = strxor(flag_ct, key[:len(flag_ct)])

	print(f"Recovered flag: {flag.decode()}")

	p.close()

if __name__ == '__main__':
	main()
