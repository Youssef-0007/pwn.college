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
 	
	# Check if the line contains the encrypted secret
        if line.startswith("- Encrypted Character:"):
            encrypted_char = line.split(":")[1].strip()
            ascii_val = ord(encrypted_char)

       
        # Check if the line contains the key
        elif line.startswith("- XOR Key:"):
            key_hex = re.search(r'0x[0-9a-fA-F]+', line).group()
            key = int(key_hex, 16)
  
            # Compute the decrypted secret
            decrypted_secret = ascii_val ^ key
            
            # Send the answer back to the challenge
            decrypted_char = chr(decrypted_secret)

            process.stdin.write(decrypted_char + '\n')
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
