from pwn import *
import sys
from Crypto.Util.Padding import pad

def oracle(ciphertext_hex):
    p = process(["/challenge/worker"])
    p.sendlineafter(b"\n", f"TASK: {ciphertext_hex}".encode())
    response = p.recvline().decode()
    p.close()
    return "Error" not in response

def decrypt_block(prev_block, target_block, known_bytes):
    block_size = 16
    decrypted = b""
    
    for i in range(1, block_size + 1):
        for guess in range(256):
            modified_prev = bytearray(prev_block)
            
            # Set bytes we already know
            for k in range(1, i):
                modified_prev[-k] = prev_block[-k] ^ known_bytes[-k] ^ i
            
            # Try current guess
            modified_prev[-i] = prev_block[-i] ^ guess ^ i
            
            # Combine with target block
            test_ciphertext = bytes(modified_prev) + target_block
            
            if oracle(test_ciphertext.hex()):
                if i == 1:  # Check if it's not just shorter padding
                    # Try with i=2 to confirm
                    modified_prev[-2] ^= 1
                    test_ciphertext = bytes(modified_prev) + target_block
                    if not oracle(test_ciphertext.hex()):
                        continue
                
                decrypted_byte = bytes([guess])
                decrypted = decrypted_byte + decrypted
                known_bytes = decrypted_byte + known_bytes
                break
    
    return decrypted

def main():
    # Get the encrypted password
    p = process(["/challenge/dispatcher", "pw"])
    line = p.recvline().decode().strip()
    p.close()
    
    ciphertext_hex = line.split()[1]
    ciphertext = bytes.fromhex(ciphertext_hex)
    iv = ciphertext[:16]
    ciphertext_blocks = [ciphertext[i:i+16] for i in range(16, len(ciphertext), 16)]
    
    # Decrypt each block
    decrypted = b""
    prev_block = iv
    
    for block in ciphertext_blocks:
        decrypted_block = decrypt_block(prev_block, block, b"")
        decrypted += decrypted_block
        prev_block = block
    
    # Remove PKCS7 padding
    pad_len = decrypted[-1]
    decrypted = decrypted[:-pad_len]
    
    print(f"Decrypted password: {decrypted.decode()}")
    
    # Redeem the flag
    p = process(["/challenge/redeem"])
    p.sendlineafter(b"Password? ", decrypted)
    print(p.recvall().decode())

if __name__ == "__main__":
    main()
