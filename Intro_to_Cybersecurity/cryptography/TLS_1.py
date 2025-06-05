import json

from pwn import *
from Crypto.PublicKey import RSA
from Crypto.Hash.SHA256 import SHA256Hash
from base64 import b64decode, b64encode

io = process(['/challenge/run'])

d_hex = io.recvregex(br'root key d: (.+)\n', capture=True).group(1).decode()
cert_b64 = io.recvregex(br'root certificate \(b64\): (.+)\n', capture=True).group(1).decode()
cert_signature_b64 = io.recvregex(br'root certificate signature \(b64\): (.+)\n', capture=True).group(1).decode()

root_d = int(d_hex, 16)
root_cert = json.loads(b64decode(cert_b64))
root_cert_signature = b64decode(cert_signature_b64)

user_key = RSA.generate(1024)

user_certificate = {
    "name": "user",
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

user_cert_b64 = b64encode(user_certificate_data)
user_sign_b64 = b64encode(user_certificate_signature)

io.readn(len('user certificate (b64): '))
io.sendline(user_cert_b64)

io.readn(len('user certificate signature (b64): '))
io.sendline(user_sign_b64)

ciphertext = io.recvregex(br'.+ ciphertext.*: (.+)\n', capture=True).group(1).decode()
ciphertext = b64decode(ciphertext)

flag = pow(int.from_bytes(ciphertext, "little"), user_key.d, user_key.n).to_bytes(256, "little")
print(flag.decode().rstrip('\0'))
