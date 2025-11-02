from pwn import *
context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug("/challenge/crafty-clobber-easy", """
b read
c
x/32gx $rsp
""")

p.sendline(b"64")
p.interactive()
