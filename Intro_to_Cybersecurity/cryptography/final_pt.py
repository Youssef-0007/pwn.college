from pwn import *
import sys

BLOCK_SIZE = 16

def oracle(ciphertext_hex):
    try:
        with process(["/challenge/worker"], timeout=2) as p:
            p.sendline(f"TASK: {ciphertext_hex}".encode())
            response = p.recvline().decode()
            return "Error" not in response
    except:
        return False

def decrypt_block(prev_ciphertext, ciphertext_block):
    intermediate = [0] * BLOCK_SIZE
    recovered = [0] * BLOCK_SIZE
    
    for byte_pos in reversed(range(BLOCK_SIZE)):
        padding_val = BLOCK_SIZE - byte_pos
        
        # Set up the crafted block for known intermediate values
        crafted = bytearray(BLOCK_SIZE)
        for i in range(byte_pos + 1, BLOCK_SIZE):
            crafted[i] = intermediate[i] ^ padding_val
        
        # Try all possible values for the current byte
        for guess in range(256):
            crafted[byte_pos] = guess
            
            # The test ciphertext is: crafted_block + target_ciphertext_block
            test_ct = bytes(crafted) + ciphertext_block
            
            if oracle(test_ct.hex()):
                # Found valid padding! Calculate intermediate value
                intermediate[byte_pos] = guess ^ padding_val
                # Calculate the actual plaintext byte
                recovered[byte_pos] = intermediate[byte_pos] ^ prev_ciphertext[byte_pos]
                print(f"Byte {byte_pos}: intermediate=0x{intermediate[byte_pos]:02x}, plaintext=0x{recovered[byte_pos]:02x} ('{chr(recovered[byte_pos]) if 32 <= recovered[byte_pos] <= 126 else '.'}')")
                break
        else:
            raise Exception(f"No valid guess found for byte position {byte_pos}")
    
    return bytes(recovered)

def main():
    # Get the encrypted flag
    with process(["/challenge/dispatcher", "flag"]) as p:
        ciphertext_hex = p.recvline().decode().split()[1]
    
    print(f"Ciphertext: {ciphertext_hex}")
    ciphertext = bytes.fromhex(ciphertext_hex)
    
    # Split into blocks (first block is IV)
    blocks = [ciphertext[i:i+BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]
    print(f"Total blocks: {len(blocks)} (including IV)")
    
    result = b''
    
    # Decrypt each block (skip the IV block)
    for i in range(len(blocks) - 1, 0, -1):
        print(f"\n[*] Decrypting block {i}")
        pt_block = decrypt_block(blocks[i-1], blocks[i])
        print(f"Decrypted block: {pt_block.hex()} | {pt_block}")
        result = pt_block + result
    
    # Remove padding
    try:
        from Crypto.Util.Padding import unpad
        result = unpad(result, BLOCK_SIZE)
        print("[+] Padding removed successfully")
    except Exception as e:
        print(f"[!] Warning: padding removal failed ({e}), keeping raw result")
    
    print(f"\n[+] Final result: {result}")
    print(f"[+] As string: {result.decode('latin1', errors='ignore')}")

if __name__ == "__main__":
    main()
