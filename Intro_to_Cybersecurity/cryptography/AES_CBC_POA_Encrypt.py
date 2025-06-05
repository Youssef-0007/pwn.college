from pwn import *
import sys
from Crypto.Util.Padding import pad

BLOCK_SIZE = 16

def oracle(ciphertext_hex):
    try:
        with process(["/challenge/worker"], timeout=2) as p:
            p.sendline(f"TASK: {ciphertext_hex}".encode())
            response = p.recvline().decode()
            return "Error" not in response
    except:
        return False

def find_intermediate_block(ciphertext_block):
    """
    Find the intermediate state for a given ciphertext block
    by using padding oracle attack
    """
    intermediate = [0] * BLOCK_SIZE
    
    for byte_pos in reversed(range(BLOCK_SIZE)):
        padding_val = BLOCK_SIZE - byte_pos
        
        # Set up the crafted block for known intermediate values
        crafted = bytearray(BLOCK_SIZE)
        for i in range(byte_pos + 1, BLOCK_SIZE):
            crafted[i] = intermediate[i] ^ padding_val
        
        # Try all possible values for the current byte
        for guess in range(256):
            crafted[byte_pos] = guess
            
            # Test with crafted block + target block
            test_ct = bytes(crafted) + ciphertext_block
            
            if oracle(test_ct.hex()):
                # Found valid padding! Calculate intermediate value
                intermediate[byte_pos] = guess ^ padding_val
                print(f"Byte {byte_pos}: intermediate=0x{intermediate[byte_pos]:02x}")
                break
        else:
            raise Exception(f"No valid guess found for byte position {byte_pos}")
    
    return bytes(intermediate)

def main():
    # Define our target message (exact string the worker expects)
    target_message = b"please give me the flag, kind worker process!"
    
    # Pad the message
    padded_message = pad(target_message, BLOCK_SIZE)
    print(f"Target message: {target_message}")
    print(f"Padded message: {padded_message} (length: {len(padded_message)})")
    print(f"Padded hex: {padded_message.hex()}")
    
    # Split into blocks
    message_blocks = [padded_message[i:i+BLOCK_SIZE] for i in range(0, len(padded_message), BLOCK_SIZE)]
    print(f"Message blocks: {len(message_blocks)}")
    for i, block in enumerate(message_blocks):
        print(f"Block {i}: {block.hex()} | {block}")
    
    # We need to forge this message completely
    # Start with a dummy ciphertext block that we'll use to get intermediate states
    dummy_block = b'\x00' * BLOCK_SIZE
    
    # We'll build the ciphertext from right to left
    forged_blocks = []
    
    # Start from the last block and work backwards
    for i in reversed(range(len(message_blocks))):
        print(f"\n[*] Forging ciphertext for plaintext block {i}: {message_blocks[i]}")
        
        if i == len(message_blocks) - 1:
            # For the last block, we need to create a ciphertext that will decrypt to our target
            # We'll use a dummy block and find its intermediate state
            print("Finding intermediate state for dummy block...")
            intermediate = find_intermediate_block(dummy_block)
            
            # Calculate what the previous ciphertext block should be
            prev_cipher = bytes([intermediate[j] ^ message_blocks[i][j] for j in range(BLOCK_SIZE)])
            
            forged_blocks.insert(0, dummy_block)  # The actual ciphertext block
            forged_blocks.insert(0, prev_cipher)  # The block that makes it decrypt correctly
        else:
            # For other blocks, use the next ciphertext block we already have
            next_cipher_block = forged_blocks[0]
            print(f"Finding intermediate state for next block: {next_cipher_block.hex()}")
            intermediate = find_intermediate_block(next_cipher_block)
            
            # Calculate what the previous ciphertext block should be
            prev_cipher = bytes([intermediate[j] ^ message_blocks[i][j] for j in range(BLOCK_SIZE)])
            
            forged_blocks.insert(0, prev_cipher)
    
    # The IV is the first element of forged_blocks
    iv = forged_blocks[0]
    ciphertext_blocks = forged_blocks[1:]
    
    final_ciphertext = iv + b''.join(ciphertext_blocks)
    
    print(f"\n[+] Final forged ciphertext: {final_ciphertext.hex()}")
    print(f"[+] Length: {len(final_ciphertext)} bytes ({len(final_ciphertext)//16} blocks)")
    
    # Test our forged message
    print(f"\n[*] Testing forged message...")
    if oracle(final_ciphertext.hex()):
        print("[+] Success! Forged message passes oracle check")
        
        # Try to get the flag by sending our forged message
        print(f"\n[*] Sending forged message to worker...")
        try:
            with process(["/challenge/worker"], timeout=5) as p:
                p.sendline(f"TASK: {final_ciphertext.hex()}".encode())
                response = p.recvall(timeout=3).decode()
                print(f"[+] Worker response:\n{response}")
                if "Victory!" in response:
                    print("[+] SUCCESS! We got the flag!")
        except Exception as e:
            print(f"[!] Error getting response: {e}")
    else:
        print("[!] Failed! Forged message does not pass oracle check")

if __name__ == "__main__":
    main()
