section .text
    global _start

_start:
    nop
    push 0x67616c66
    mov rdi, rsp
    mov si, 0x1ff      ; Mode 0777
    mov al, 90         ; chmod syscall = 90
    syscall

