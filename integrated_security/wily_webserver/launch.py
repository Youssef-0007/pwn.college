#!/usr/bin/env python3
import subprocess
import os
import time
import signal

binary = "/challenge/integration-web-overflow"
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

print("[*] Ready to trigger the vulnerable path.")
print(">>> Use curl in another terminal:")
print("    curl http://localhost:80/hacker_manifesto.txt")
print("\n[!] Press Ctrl+C here when done.")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[*] Cleaning up server...")
    os.killpg(os.getpgid(server_proc.pid), signal.SIGTERM)
    server_proc.wait()
