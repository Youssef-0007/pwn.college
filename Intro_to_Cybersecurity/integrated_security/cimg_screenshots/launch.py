#!/usr/bin/env python3
import subprocess
import os
import time

binary = "/challenge/integration-cimg-screenshot-sc"
exploit = "exploit.cimg"
env = {}

# Start the binary but sleep before sending input
print("[*] Launching challenge binary...")

# Use preexec_fn=os.setsid to isolate the process group
p = subprocess.Popen(
    [binary],
    stdin=subprocess.PIPE,
    preexec_fn=os.setsid,
    env=env
)

print(f"[!] Pause and attach to PID {p.pid} using: sudo gdb -p {p.pid}")
input(">>> Press Enter after attaching GDB and setting breakpoints...")

# After attaching, resume and send exploit
with open(exploit, "rb") as f:
    payload = f.read()
    print("[*] Sending exploit...")
    p.stdin.write(payload)
    p.stdin.close()

p.wait()
