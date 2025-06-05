from pwn import xor 

encrpted_flag = "0e45b719d00b5d8f1fe9af46b9305d38f97b191e60c6b2c645d817e6c1b3461a21899fe10606c0a65331afef3be7927fb446d54f9f7492c32d8d8f30"
key_hex = "7e32d937b36431e37a8eca3d8d68306d9c36587b32b0dc9c09ab428e85d0207c6ff9af8c686a928802699f8c41aae808cd08ac2ce539e58657daf23a"

# Convert hex strings to bytes
encrypted_flag_bytes = bytes.fromhex(encrpted_flag)
key_bytes = bytes.fromhex(key_hex)

decrypted_flag_bytes = xor(encrypted_flag_bytes, key_bytes)

flag = decrypted_flag_bytes.decode("utf-8")

print("Decrypted Flag:", flag)
