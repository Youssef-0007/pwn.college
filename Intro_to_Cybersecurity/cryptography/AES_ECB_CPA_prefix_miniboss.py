from pwn import *
import sys

# Configure character set and block size
charset = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}-!?."
block_size = 16

def connect_to_challenge():
    p = process("/challenge/run")
    return p

def prepend_and_encrypt(p, data):
    p.sendlineafter(b"Data? ", data.hex())
    return p.recvline().decode().split()[-1]

def determine_flag_length(p):
    """Estimate flag length by prepending 15 bytes"""
    ct = prepend_and_encrypt(p, b"A"*15)
    #print(f"ct from determine the flag length: {ct}")
    return len(bytes.fromhex(ct)) - block_size

def recover_block(p, known_flag, target_block):
    """Recover a specific block of the flag"""
    block_content = b""
    
    for pos_in_block in range(block_size):
        # Calculate padding to isolate next byte
        total_pad = (block_size - 1 - pos_in_block - (len(known_flag) % block_size)) % block_size
        
        # Get target ciphertext
        prepended_ct = prepend_and_encrypt(p, b"A"*total_pad)
        ct_blocks = [prepended_ct[i:i+32] for i in range(0, len(prepended_ct), 32)]
        target_ct = ct_blocks[target_block]
        
        # Brute-force the next byte
        found = False
        for c in charset:
            test_input = b"A"*total_pad + known_flag + block_content + bytes([c])
            test_ct = prepend_and_encrypt(p, test_input)
            
            if test_ct[target_block * 32 : (target_block * 32) + 32] == target_ct:
                block_content += bytes([c])
                print(f"Found: {block_content.decode()}")
                found = True
                break
                
        if not found:
            break
            
    return block_content

def recover_full_flag():
    p = connect_to_challenge()
    
    try:
        # Step 1: Determine flag length
        flag_len = determine_flag_length(p)
        print(f"Flag length: ~{flag_len} bytes")
        
        # Step 2: Recover blocks sequentially
        known_flag = b""
        total_blocks = (flag_len + block_size - 1) // block_size
        
        for block_num in range(total_blocks):
            print(f"\nRecovering block {block_num + 1}/{total_blocks}")
            block = recover_block(p, known_flag, block_num)
            known_flag += block
            print(f"Current flag: {known_flag.decode()}")
            
            # Early exit if we hit the end
            if known_flag.endswith(b"}"):
                break
                
    finally:
        p.close()
    
    return known_flag

if __name__ == "__main__":
    flag = recover_full_flag()
    print("\nFinal flag:", flag.decode())
