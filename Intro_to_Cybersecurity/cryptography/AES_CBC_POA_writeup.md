### **Padding Oracle Attack Challenge Series Writeups**

This series of challenges demonstrates how **AES-CBC mode with PKCS7 padding** can be vulnerable to **Padding Oracle Attacks**. Each challenge builds on the previous one, introducing new complexities.

---

## **1. Partial Block Challenge**
### **Challenge Description**
- **Scenario**: The plaintext is shorter than a full block (16 bytes), so padding is added to the same block.
- **Goal**: Decrypt the message by exploiting padding validation.

### **Attack Steps**
1. **Intercept the ciphertext** (IV + single encrypted block).
2. **Brute-force the last byte**:
   - Modify the IV's last byte until padding is valid (`\x01`).
   - Calculate the plaintext byte: `plaintext[-1] = original_IV[-1] ^ modified_IV[-1] ^ 0x01`.
3. **Repeat for previous bytes**:
   - For byte `i`, set padding to `i` and brute-force the correct value.

### **Key Insight**
- The padding oracle leaks plaintext bytes one at a time.
- Only the IV needs to be modified since there’s just one block.

### **Solution Code**
```python
from pwn import *

def oracle(ciphertext_hex):
    p = process(["/challenge/worker"])
    p.sendline(f"TASK: {ciphertext_hex}".encode())
    return "Error" not in p.recvline().decode()

def decrypt_block(iv, ciphertext_block):
    plaintext = b""
    for i in range(1, 17):
        for guess in range(256):
            modified_iv = bytearray(iv)
            modified_iv[-i] ^= guess ^ i
            if oracle(bytes(modified_iv).hex() + ciphertext_block.hex()):
                plaintext = bytes([guess]) + plaintext
                break
    return plaintext

iv = bytes.fromhex("...")  # Given IV
ciphertext_block = bytes.fromhex("...")  # Given ciphertext
print(decrypt_block(iv, ciphertext_block))
```

---

## **2. Full Block Challenge**
### **Challenge Description**
- **Scenario**: The plaintext is exactly 16 bytes, so PKCS7 adds a full block of padding (`\x10` repeated).
- **Goal**: Decrypt the full block, ignoring the padding block.

### **Attack Steps**
1. **Identify the ciphertext structure**:
   - `IV | Encrypted_Block1 | Encrypted_Padding_Block`.
2. **Decrypt `Block1`**:
   - Modify the IV to brute-force plaintext bytes (same as partial block).
3. **Discard the padding block** (since we know it's `\x10\x10...`).

### **Key Insight**
- The padding block is predictable, so we only need to decrypt the first block.
- The attack is identical to the partial block case but with an extra (ignored) block.

### **Solution Code**
*(Same as Partial Block, but with an extra block in ciphertext.)*

---

## **3. Multi-Block Challenge**
### **Challenge Description**
- **Scenario**: The plaintext spans multiple blocks (e.g., the actual flag).
- **Goal**: Decrypt all blocks by chaining the attack.

### **Attack Steps**
1. **Split ciphertext into blocks**:
   - `IV | Block1 | Block2 | ... | BlockN`.
2. **Decrypt from last to first**:
   - For `BlockN`, modify `BlockN-1` to brute-force plaintext.
   - For `BlockN-1`, modify `BlockN-2`, and so on.
   - For `Block1`, modify the IV.
3. **Combine results and remove padding**.

### **Key Insight**
- Each block depends on the previous ciphertext block (or IV).
- The attack must process blocks in reverse order.

### **Solution Code**
```python
from pwn import *

def oracle(ciphertext_hex):
    p = process(["/challenge/worker"])
    p.sendline(f"TASK: {ciphertext_hex}".encode())
    return "Error" not in p.recvline().decode()

def decrypt_block(prev_block, target_block):
    plaintext = b""
    for i in range(1, 17):
        for guess in range(256):
            modified_prev = bytearray(prev_block)
            modified_prev[-i] ^= guess ^ i
            if oracle(bytes(modified_prev).hex() + target_block.hex()):
                plaintext = bytes([guess]) + plaintext
                break
    return plaintext

ciphertext = bytes.fromhex("...")  # Full ciphertext (IV + blocks)
blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
result = b""

for i in reversed(range(1, len(blocks))):
    result = decrypt_block(blocks[i-1], blocks[i]) + result

print(result[:-result[-1]])  # Remove PKCS7 padding
```

---

## **Comparison of All Challenges**
| Challenge       | Block Structure               | Attack Modifications          | Key Insight |
|----------------|-----------------------------|-----------------------------|------------|
| **Partial Block** | `IV + Block1` (partial + padding) | Modify IV only | Last byte leaks first |
| **Full Block** | `IV + Block1 + PaddingBlock` | Modify IV, ignore padding block | Padding block is predictable |
| **Multi-Block** | `IV + Block1 + Block2 + ...` | Modify previous block for each | Must decrypt in reverse |

### **Key Takeaways**
1. **Partial Block**: Simplest case, modify IV only.
2. **Full Block**: Like partial block, but with an extra padding block.
3. **Multi-Block**: Must chain decryption from last block to first.

All attacks exploit the same core vulnerability: **the padding oracle leaks plaintext bytes**. The only difference is how many blocks are involved and which parts of the ciphertext must be modified. 
