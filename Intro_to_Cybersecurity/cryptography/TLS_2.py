import json

from pwn import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash.SHA256 import SHA256Hash
from Crypto.Util.Padding import pad, unpad
from base64 import b64decode

def encrypt_input(cipher, data):
    return cipher.encrypt(pad(data, cipher.block_size))

io = process(['/challenge/run'])

p_hex = io.recvregex(br'p: (.+)\n', capture=True).group(1).decode()
g_hex = io.recvregex(br'g: (.+)\n', capture=True).group(1).decode()

d_hex = io.recvregex(br'root key d: (.+)\n', capture=True).group(1).decode()
cert_b64 = io.recvregex(br'root certificate \(b64\): (.+)\n', capture=True).group(1).decode()
cert_signature_b64 = io.recvregex(br'root certificate signature \(b64\): (.+)\n', capture=True).group(1).decode()

name = io.recvregex(br'name: (.+)\n', capture=True).group(1).decode()
A_hex = io.recvregex(br'A: (.+)\n', capture=True).group(1).decode()

p = int(p_hex, 16)
g = int(g_hex, 16)
A = int(A_hex, 16)

root_d = int(d_hex, 16)
root_cert = json.loads(b64decode(cert_b64))
root_cert_signature = b64decode(cert_signature_b64)

b = random.getrandbits(1024)
B = pow(g, b, p)
s = pow(A, b, p)

io.readn(len('B: '))
io.sendline(hex(B).encode())

key = SHA256Hash(s.to_bytes(256, "little")).digest()[:16]
cipher_encrypt = AES.new(key=key, mode=AES.MODE_CBC, iv=b"\0"*16)
cipher_decrypt = AES.new(key=key, mode=AES.MODE_CBC, iv=b"\0"*16)

user_key = RSA.generate(1024)

user_certificate = {
    "name": name,
    "key": {
        "e": user_key.e,
        "n": user_key.n,
    },
    "signer": root_cert["signer"],
}

user_certificate_data = json.dumps(user_certificate).encode()
user_certificate_hash = SHA256Hash(user_certificate_data).digest()
user_certificate_signature = pow(
    int.from_bytes(user_certificate_hash, "little"),
    root_d,
    int(root_cert["key"]["n"])
).to_bytes(256, "little")

user_cert_b64 = base64.b64encode(encrypt_input(cipher_encrypt, user_certificate_data))
user_sign_b64 = base64.b64encode(encrypt_input(cipher_encrypt, user_certificate_signature))

user_signature_data = (
    name.encode().ljust(256, b"\0") +
    A.to_bytes(256, "little") +
    B.to_bytes(256, "little")
)

usd_data_hash = SHA256Hash(user_signature_data).digest()
usd_signature = pow(
    int.from_bytes(usd_data_hash, "little"),
    user_key.d,
    user_key.n
).to_bytes(256, "little")

usd_signature_b64 = base64.b64encode(encrypt_input(cipher_encrypt, usd_signature))

io.readn(len('user certificate (b64): '))
io.sendline(user_cert_b64)

io.readn(len('user certificate signature (b64): '))
io.sendline(user_sign_b64)

io.readn(len('user signature (b64): '))
io.sendline(usd_signature_b64)

ciphertext = io.recvregex(br'.+ ciphertext.*: (.+)\n', capture=True).group(1).decode()
ciphertext = b64decode(ciphertext)

flag = unpad(cipher_decrypt.decrypt(ciphertext), cipher_decrypt.block_size)
print(flag.decode())
