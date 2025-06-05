import subprocess
from Crypto.Util.strxor import strxor

def solve_challenge():
    # Start the challenge process
    process = subprocess.Popen(['/challenge/run'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    
    while True:
        # Read a line from the challenge output
        line = process.stdout.readline()
        if not line:
            break  # End of output
        
        print(line.strip(), flush=True)  # Print challenge output for debugging
        
        # Check if the line contains the encrypted string
        if line.startswith("- Encrypted String:"):
            encrypted_str = line.split(":")[1].strip()
        
        # Check if the line contains the XOR key string
        elif line.startswith("- XOR Key String:"):
            key_str = line.split(":")[1].strip()
            
            # Convert strings to bytes
            encrypted_bytes = encrypted_str.encode('utf-8')
            key_bytes = key_str.encode('utf-8')
            
            # Perform XOR operation
            decrypted_bytes = strxor(encrypted_bytes, key_bytes)
            
            # Convert bytes back to string
            decrypted_str = decrypted_bytes.decode('utf-8')
            
            # Send the answer back to the challenge
            process.stdin.write(decrypted_str + '\n')
            process.stdin.flush()
            
            # Print the answer for debugging
            print(f"Decrypted String: {decrypted_str}", flush=True)

    # Close the process
    process.stdin.close()
    process.stdout.close()
    process.stderr.close()
    process.wait()

if __name__ == "__main__":
    solve_challenge()
