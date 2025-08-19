#!/usr/bin/env python3
import subprocess
import os
import time
import signal

binary = "/challenge/server"
env = {}  # Clean environment (optional)

print("[*] Launching server in background...")

# Start the server paused using SIGSTOP so we can attach before execution
server_proc = subprocess.Popen(
    [binary],
    preexec_fn=os.setsid,
    env=env
)

print(f"[!] Server PID: {server_proc.pid}")
print(f"[!] Attaching to server. Use:")
print(f"    sudo gdb -p {server_proc.pid}")
print(">>> Set a breakpoint at `challenge` function.")
print(">>> Then type `continue` inside GDB to resume execution.")

# Give time to ensure process is started
time.sleep(1)

# Pause the server so GDB can attach before anything runs
print("[*] Sending SIGSTOP to pause server before it runs.")
os.kill(server_proc.pid, signal.SIGSTOP)

input(">>> Press Enter once you've attached GDB and set breakpoints...")

# Resume execution after GDB attach and breakpoint set
print("[*] Resuming server execution.")
os.kill(server_proc.pid, signal.SIGCONT)

print(">>> You can now trigger the exploit manually, e.g.:")
print("    curl http://localhost:80/hacker_manifesto.txt")
print("\n[!] Press Ctrl+C here when done.")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[*] Cleaning up server...")
    os.killpg(os.getpgid(server_proc.pid), signal.SIGTERM)
    server_proc.wait()
