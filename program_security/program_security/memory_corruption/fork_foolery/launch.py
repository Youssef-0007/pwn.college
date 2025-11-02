#!/usr/bin/env python3
from pwn import *
import subprocess
import os
import time
import signal

binary = "/challenge/fork-foolery-hard"
env = os.environ.copy()
env = {}  # Optional, in case your system supports it

print("[*] Launching server in background...")
server_proc = subprocess.Popen(
    [binary],
    preexec_fn=os.setsid,
    env=env
)

print(f"[!] Attach to PID {server_proc.pid} using:")
print(f"    sudo gdb -p {server_proc.pid}")
print(">>> Set breakpoints in `send_file` or `handle_connection`.")

input(">>> Press Enter after GDB is attached and breakpoints are set...")

'''
r = remote("localhost", 1337)

r.recvuntil("Payload size")
r.sendline(b'8')

#r.recvuntil("Send your payload")
#time.sleep(5)
#payload = b'\x90' * 8
#r.send(payload)

r.interactive()
'''
