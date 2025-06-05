from pwn import *

charset = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}-!?."
block_size = 16

def encrypt(pt):
    p.sendlineafter(b"Choice? ", b"1")
    p.sendlineafter(b"Data? ", pt)  # Send raw bytes
    return p.recvline().decode().split()[-1].strip()

def encrypt_flag_tail(length):
    p.sendlineafter(b"Choice? ", b"2")
    p.sendlineafter(b"Length? ", str(length).encode())
    return p.recvline().decode().split()[-1].strip()

def recover_flag(p):
    known = b"}"
    codebook = {}
    
    while True:
        found = False
        for c in charset:
            # Build candidate: new byte + known suffix
            candidate = bytes([c]) + known
            
            # Check if we already know this ciphertext
            if candidate in codebook.values():
                continue
                
            # Get ciphertext for this candidate
            ct_candidate = encrypt(candidate)
            
            # Get ciphertext for flag tail
            ct_flag = encrypt_flag_tail(len(candidate))
            
            if ct_candidate == ct_flag:
                known = bytes([c]) + known
                codebook[ct_candidate] = known
                print(f"Progress: {known.decode()}")
                found = True
                break
                
        if not found:
            break
            
    return known

p = process("/challenge/run")
flag = recover_flag(p)
print("Final flag:", flag.decode())
p.close()
