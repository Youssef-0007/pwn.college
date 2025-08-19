section .text
global _start


_start:
    ; accept(3, NULL, NULL)
    mov rax, 43         ; syscall number for accept
    mov rdi, 3          ; fd 3 (the original server socket)
    xor rsi, rsi        ; NULL addr
    xor rdx, rdx        ; NULL addrlen
    syscall             ; returns new client fd in rax

    ; save accepted socket fd
    mov rdi, rax        ; rdi = new accepted socket

    ; read(rdi, rsp, 300)
    mov rax, 0          ; syscall number for read
    mov rsi, rsp        ; buffer on stack
    mov rdx, 300        ; read 300 bytes
    syscall             ; returns number of bytes read in rax

    ; write(1, rsp, rax)
    mov rdi, 1          ; stdout
    mov rax, 1          ; syscall number for write
    syscall

    ; exit(0)
    mov rax, 60         ; syscall number for exit
    xor rdi, rdi
    syscall
