import re
import subprocess

def solve_challenge():
    # Start the challenge process
    process = subprocess.Popen(['/challenge/run'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    
    while True:
        # Read a line from the challenge output
        line = process.stdout.readline()
        if not line:
            break  # End of output
        
        print(line.strip())  # Optional: print challenge output for debugging
        
        # Check if the line contains the key
        if line.startswith("The key:"):
            key_hex = re.search(r'0x[0-9a-fA-F]+', line).group()
            key = int(key_hex, 16)
        
        # Check if the line contains the encrypted secret
        elif line.startswith("Encrypted secret:"):
            encrypted_hex = re.search(r'0x[0-9a-fA-F]+', line).group()
            encrypted_secret = int(encrypted_hex, 16)
            
            # Compute the decrypted secret
            decrypted_secret = encrypted_secret ^ key
            
            # Send the answer back to the challenge
            answer_hex = f"{decrypted_secret:#04x}"
            process.stdin.write(answer_hex + '\n')
            process.stdin.flush()
            
            # Optional: print the answer for debugging
            print(f"Decrypted secret? {answer_hex}")

    # Close the process
    process.stdin.close()
    process.stdout.close()
    process.stderr.close()
    process.wait()

if __name__ == "__main__":
    solve_challenge()
