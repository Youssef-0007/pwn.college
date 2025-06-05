from pwn import *
from Crypto.Util.Padding import pad

# Expanded character set based on common flag formats
charset = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}-!?."

def build_codebook(p):
    """Build mapping of single characters to their encrypted blocks"""
    codebook = {}
    for c in charset:
        # Get encryption of single character (exactly like the challenge does)
        p.sendlineafter(b"Choice? ", b"1")
        p.sendlineafter(b"Data? ", bytes([c]))  # Send raw character, no hex
        ct_hex = p.recvline().decode().split()[-1].strip()
        ct = bytes.fromhex(ct_hex)
        codebook[ct] = c
        print(f"Learned: {chr(c)} -> {ct.hex()}")
    return codebook

def extract_flag(p, codebook, flag_length=59):
    """Extract flag by comparing individual character encryptions"""
    flag = bytearray()
    
    for i in range(flag_length):
        # Get encrypted version of flag[i]
        p.sendlineafter(b"Choice? ", b"2")
        p.sendlineafter(b"Index? ", str(i).encode())
        p.sendlineafter(b"Length? ", b"1")
        ct_hex = p.recvline().decode().split()[-1].strip()
        ct = bytes.fromhex(ct_hex)
        
        # Find matching character in codebook
        if ct in codebook:
            flag.append(codebook[ct])
            print(f"Found position {i}: {chr(codebook[ct])}")
        else:
            flag.append(ord('?'))
            print(f"Unknown at {i}: {ct.hex()}")
        
        # Early exit if we find closing brace
        if flag.endswith(b"}"):
            break
    
    return flag.decode(errors="replace")

if __name__ == "__main__":
    p = process('/challenge/run')
    try:
        print("Building codebook...")
        codebook = build_codebook(p)
        print(f"\nBuilt codebook with {len(codebook)} entries\n")
        
        print("Extracting flag...")
        flag = extract_flag(p, codebook)
        print("\nRecovered flag:", flag)
    finally:
        p.close()
