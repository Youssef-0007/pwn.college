from pwn import *
import sys

# Configuration
charset = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}-!?."
block_size = 16

def connect_to_challenge():
    return process("/challenge/run")

def encrypt(p, data):
    p.sendlineafter(b"Choice? ", b"1")
    p.sendlineafter(b"Data? ", data)
    return p.recvline().decode().split()[-1]

def prepend_and_encrypt(p, data):
    p.sendlineafter(b"Choice? ", b"2")
    p.sendlineafter(b"Data? ", data)
    return p.recvline().decode().split()[-1]

def recover_flag():
    p = connect_to_challenge()
    known_flag = b""
    
    try:
        # First determine how many blocks the flag has by prepending nothing
        base_ct = prepend_and_encrypt(p, b"")
        num_blocks = len(base_ct) // 32  # 32 hex chars per block
        print(f"Flag uses {num_blocks} blocks")
        
        # We'll recover one block at a time
        for block_num in range(num_blocks):
            print(f"\n=== Recovering block {block_num + 1}/{num_blocks} ===")
            
            # For each position in the block (0-15)
            for pos in range(block_size):
                # Calculate padding needed to align target byte
                pad_len = (block_size - pos - 1) % block_size
                
                # Get the ciphertext with this padding
                ct = prepend_and_encrypt(p, b"A"*pad_len)
                target_block = ct[block_num*32:(block_num+1)*32]
                
                # Try each possible character
                for c in charset:
                    # Build test input: padding + known + new char
                    test_input = b"A"*pad_len + known_flag + bytes([c])
                    test_ct = encrypt(p, test_input)
                    
                    # Compare first block of test with target block
                    if test_ct[block_num*32:(block_num+1)*32] == target_block:
                        known_flag += bytes([c])
                        print(f"Found: {known_flag.decode()}")
                        break
            
            print(f"\nBlock {block_num + 1} complete: {known_flag.decode()}")
            
            # Stop if we've found the end
            if known_flag.endswith(b"}"):
                break
                
    finally:
        p.close()
    
    return known_flag

print("\nFinal flag:", recover_flag().decode())
