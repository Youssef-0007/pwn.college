## 🧠 CIMG Screenshots Exploit — Analytical Writeup

### 🎯 Objective

Exploit a vulnerability in how a `.cimg` image file is processed by a custom binary located at `/challenge/integration-cimg-screenshot-sc`. The goal is to **achieve arbitrary code execution** by injecting shellcode and redirecting execution flow to it in order to spawn a shell and read `/flag`.

---

### 🔍 Vulnerability Analysis

While reversing the binary, we identified two important functions:

* `handle_4`: Copies attacker-controlled sprite data into a framebuffer.
* `handle_1337`: Copies that framebuffer data onto the stack without proper bounds checking.

This **stack buffer overflow** opens the door for overwriting the return address. Our approach revolved around:

* Injecting a valid shellcode payload into a sprite.
* Letting `handle_4` copy it into heap (framebuffer).
* Letting `handle_1337` blindly copy it to the stack.
* Overwriting the return address to point to our shellcode.

---

### 🧩 Initial Problems & Constraints

* The binary is **SUID** and **ASLR-protected**.
* **No source code or debugging symbols**.
* **No `sudo`** access — `gdb attach` often failed (`ptrace: Operation not permitted`).
* Environment variables introduce inconsistency in stack layout due to ASLR.

---

### 🧠 Reasoning Behind Our Attempts

We tried **multiple approaches**, each driven by specific challenges:

---

#### 1️⃣ Attaching GDB with Breakpoints (`int3`)

**Why we tried this**:
To debug reliably without needing an initial breakpoint inside the binary, we inserted `int3` in our shellcode to trigger a trap and give us a place to attach `gdb`.

**What we hoped**:
Attach mid-execution and inspect memory/registers to verify shellcode placement.

**Result**:
Didn’t work reliably due to:

* ASLR shifting stack addresses
* `gdb attach` failing because of missing `sudo`
* Process often exited too fast before `gdb` could attach

---

#### 2️⃣ GDB Attaching with Manual Pause

**Why we tried this**:
To control when we attach `gdb`, we paused execution before sending the `.cimg` file.

**How**:
Inserted a manual pause in a Python script that launched the binary via subprocess. This gave us time to attach `gdb` before the overflow occurs.

**What we hoped**:
Break at known safe spot (e.g., `handle_1337`) to inspect and adjust stack offsets.

**Result**:
Partially worked in theory — but `gdb` attaching still failed in the actual challenge environment (no `ptrace` permission).

---

#### 3️⃣ Analyzing Stack Layout in Practice Mode

**Why we tried this**:
Needed **stable memory addresses** to know where shellcode would land.

**How**:
Used GDB in **practice mode**, with **`env -i`** to clear environment variables and disable ASLR randomness caused by variable size.

```bash
env -i gdb /challenge/integration-cimg-screenshot-sc
set disable-randomization on
run exploit.cimg
info frame
```

**What we hoped**:
Get consistent and clean stack layout (return address and buffer location).

**Result**: ✅
This gave us the exact offset between the buffer and return address (176 bytes), and reliable shellcode address on the stack.

---

#### 4️⃣ Using `execve("/bin/sh", NULL, NULL)` Instead of open/read/write

**Why we tried this**:
Shellcode to open/read `/flag` failed inside `gdb` (likely due to permission issues on SUID binary). Using `execve` to spawn a shell was:

* Simpler
* More reliable
* Compatible with the challenge setup

**Result**: ✅
In real execution, it provided a shell where we could run `cat /flag`.

---

#### 5️⃣ Running Exploit in Clean Environment with `env -i`

**Why we tried this**:
To reproduce the **same memory layout** we saw during practice GDB runs (no environment = more predictable stack layout).

**How**:

```bash
env -i /challenge/integration-cimg-screenshot-sc exploit.cimg
```

**Result**: ✅
Shellcode landed at the expected address, return address was hit correctly, and shell was spawned.

---

### 📜 Final Working Flow

1. Used **practice mode + `gdb` + `env -i`** to inspect clean memory layout.
2. Confirmed **offsets** (176 bytes) and **target address** on the stack.
3. Created payload with **NOP sled + shellcode + return address**.
4. Used `execve("/bin/sh", NULL, NULL)` in shellcode for better reliability.
5. Executed in real environment using:

```bash
env -i /challenge/integration-cimg-screenshot-sc exploit.cimg
```

6. Gained shell → `cat /flag`.

---

### 🧠 Key Concepts Learned

* **Stack-based buffer overflow** via indirect copy (`memcpy` to stack).
* **Impact of ASLR and environment size** on memory layout.
* **Why `execve` is more reliable** than open/read/write shellcode in restricted binaries.
* **How to debug SUID/ASLR binaries** without `sudo` or attaching `gdb`.
* **Stack alignment issues** can be avoided with NOP sleds.
* The importance of **practice environments** to extract stable offsets in unstable real targets.
