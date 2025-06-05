# AES-ECB Chosen Prefix Attack Writeup

## Challenge Overview

This challenge demonstrates a classic cryptographic attack against AES in ECB (Electronic Codebook) mode when an attacker can prepend arbitrary data to a secret before encryption. The server allows us to:
1. Encrypt chosen plaintexts (option 1)
2. Prepend data to the flag before encryption (option 2)

## Key Vulnerability: ECB Mode Weakness

ECB mode encrypts identical plaintext blocks to identical ciphertext blocks. When we can control data prepended to the secret:
- We can **align the flag's bytes at block boundaries**
- **Isolate individual characters** by careful padding
- **Brute-force characters** by comparing ciphertext blocks

## Attack Methodology

### 1. Determine Flag Length
```python
ct = prepend_and_encrypt(p, b"A"*15)
flag_len = len(bytes.fromhex(ct)) - block_size
```
By prepending 15 bytes, we can estimate the flag length from the ciphertext size.

### 2. Recover Blocks Sequentially
For each block (from first to last):
1. **Calculate padding** to align target block
2. **Isolate target block** in ciphertext
3. **Recover bytes** by brute-forcing possible characters

### 3. Byte-by-Byte Recovery
For each position in the block:
```python
total_pad = (block_size - 1 - pos_in_block - (len(known_flag) % block_size)) % block_size
test_input = b"A"*total_pad + known_flag + block_content + bytes([c])
if test_ct[target_block*32:(target_block*32)+32] == target_ct:
    block_content += bytes([c])
```

## Solution Code Walkthrough

```python
from pwn import *
import sys

charset = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}-!?."
block_size = 16

def connect_to_challenge():
    p = process("/challenge/run")
    return p

def encrypt(p, data):
    p.sendlineafter(b"Choice? ", b"1")
    p.sendlineafter(b"Data? ", data)
    return p.recvline().decode().split()[-1]

def prepend_and_encrypt(p, data):
    p.sendlineafter(b"Choice? ", b"2")
    p.sendlineafter(b"Data? ", data)
    return p.recvline().decode().split()[-1]

def determine_flag_length(p):
    ct = prepend_and_encrypt(p, b"A"*15)
    return len(bytes.fromhex(ct)) - block_size

def recover_block(p, known_flag, target_block):
    block_content = b""
    for pos_in_block in range(block_size):
        total_pad = (block_size - 1 - pos_in_block - (len(known_flag) % block_size)) % block_size
        prepended_ct = prepend_and_encrypt(p, b"A"*total_pad)
        ct_blocks = [prepended_ct[i:i+32] for i in range(0, len(prepended_ct), 32)]
        target_ct = ct_blocks[target_block]
        
        for c in charset:
            test_input = b"A"*total_pad + known_flag + block_content + bytes([c])
            test_ct = encrypt(p, test_input)
            
            if test_ct[target_block*32:(target_block*32)+32] == target_ct:
                block_content += bytes([c])
                print(f"Found: {block_content.decode()}")
                break
                
    return block_content

def recover_full_flag():
    p = connect_to_challenge()
    known_flag = b""
    flag_len = determine_flag_length(p)
    total_blocks = (flag_len + block_size - 1) // block_size
    
    for block_num in range(total_blocks):
        block = recover_block(p, known_flag, block_num)
        known_flag += block
        if known_flag.endswith(b"}"):
            break
            
    p.close()
    return known_flag

print("Final flag:", recover_full_flag().decode())
```

## Attack Visualization

### Example for First Block Recovery
1. **Initial State**:
   ```
   [FLAG BLOCK 1][FLAG BLOCK 2]...
   ```

2. **Prepend 15 'A's**:
   ```
   [15xA][F][LAG BLOCK 1...]
   ```

3. **Find first character**:
   - Test `[15xA][A]`, `[15xA][B]`, ... until ciphertext matches
   - When `[15xA][p]` matches, we know first character is 'p'

4. **Continue to next character**:
   - Now prepend 14 'A's: `[14xA][p][?]`
   - Test second character positions

### Block Alignment Math
The key formula:
```python
total_pad = (block_size - 1 - pos_in_block - (len(known_flag) % block_size) % block_size
```
This calculates exactly how much padding is needed to push the next unknown byte to a block boundary where we can test it.

## Why This Works

1. **ECB Determinism**: Same plaintext blocks → same ciphertexts
2. **Controlled Alignment**: Precise padding isolates bytes
3. **Block Isolation**: Each character can be tested independently
4. **Progressive Recovery**: Builds the flag from start to end

## Lessons Learned

1. **Never use ECB mode** for encrypting multiple blocks of sensitive data
2. **Prepending attacks** are powerful when possible
3. **Block alignment** is crucial for these attacks
4. **Padding calculations** must be exact for successful exploitation

This attack demonstrates how even limited control over plaintext input (just prepending data) can lead to complete compromise of secret data when using ECB mode.
