# AES-ECB Chosen Plaintext Attack (CPA) Writeup

## Challenge Overview
This challenge demonstrates a fundamental weakness in the Electronic Codebook (ECB) mode of AES encryption. The vulnerability allows an attacker to decrypt the flag by building a codebook of known plaintext-ciphertext pairs.

## Key Vulnerability
ECB mode encrypts identical plaintext blocks to identical ciphertext blocks independently. This means:
- Encrypting the same 16-byte block multiple times will always produce the same ciphertext
- We can build a dictionary mapping plaintext blocks to their ciphertexts
- By comparing encrypted flag blocks to our dictionary, we can decrypt the flag

## Attack Methodology

### Step 1: Build the Codebook
1. **Character Set Selection**:
   - We use all alphanumeric characters plus common symbols (`A-Za-z0-9_{}-!?`)
   - This covers all likely flag characters while keeping the codebook manageable

2. **Codebook Construction**:
   ```python
   for c in charset:
       p.sendlineafter(b"Choice? ", b"1")
       p.sendlineafter(b"Data? ", bytes([c]))  # Send raw byte
       ct = p.recvline().split()[-1]  # Get ciphertext
       codebook[bytes.fromhex(ct)] = c
   ```
   - For each character, we:
     1. Choose the "encrypt chosen plaintext" option
     2. Send the single character (automatically padded to 16 bytes by the server)
     3. Store the ciphertext mapping

### Step 2: Extract the Flag
1. **Flag Length Determination**:
   - We know the flag is 59 characters long (indices 0-58)
   
2. **Character-by-Character Decryption**:
   ```python
   for i in range(59):
       p.sendlineafter(b"Choice? ", b"2")
       p.sendlineafter(b"Index? ", str(i).encode())
       p.sendlineafter(b"Length? ", b"1")
       flag_ct = bytes.fromhex(p.recvline().split()[-1])
       flag.append(codebook.get(flag_ct, ord('?')))
   ```
   - For each flag position:
     1. Request encryption of that single character
     2. Look up the ciphertext in our codebook
     3. Append the matching plaintext character

## Why This Works
1. **Consistent Padding**:
   - The server pads single characters to 16 bytes the same way for both:
     - Our chosen plaintexts (option 1)
     - The flag characters (option 2)

2. **ECB Determinism**:
   - `encrypt(pad("p"))` always equals `encrypt(first_flag_character)`
   - This allows direct ciphertext comparison

3. **Complete Coverage**:
   - Our character set includes all possible flag characters
   - Each ciphertext has an exact match in our codebook

## Solution Code
```python
from pwn import *

charset = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}-!?"

def build_codebook(p):
    codebook = {}
    for c in charset:
        p.sendlineafter(b"Choice? ", b"1")
        p.sendlineafter(b"Data? ", bytes([c]))
        ct_hex = p.recvline().decode().split()[-1].strip()
        codebook[bytes.fromhex(ct_hex)] = c
    return codebook

def extract_flag(p, codebook):
    flag = bytearray()
    for i in range(59):  # Known flag length
        p.sendlineafter(b"Choice? ", b"2")
        p.sendlineafter(b"Index? ", str(i).encode())
        p.sendlineafter(b"Length? ", b"1")
        ct_hex = p.recvline().decode().split()[-1].strip()
        flag.append(codebook.get(bytes.fromhex(ct_hex), ord('?')))
    return flag.decode()

p = process('/challenge/run')
codebook = build_codebook(p)
flag = extract_flag(p, codebook)
print("Flag:", flag)
p.close()
```

## Lessons Learned
1. **ECB Mode Weaknesses**:
   - Never use ECB for encrypting multiple blocks of sensitive data
   - Identical plaintext blocks leak information through identical ciphertexts

2. **Padding Considerations**:
   - Understanding how padding works is crucial for crypto attacks
   - The attack works because padding is consistent between operations

3. **Chosen Plaintext Attacks**:
   - When attackers can encrypt arbitrary data, they can build decryption dictionaries
   - This is why modern cryptosystems must resist chosen plaintext attacks

This challenge demonstrates why ECB mode is insecure for most real-world uses and how cryptographic padding can affect attack viability. The solution efficiently exploits these weaknesses to recover the complete flag.
