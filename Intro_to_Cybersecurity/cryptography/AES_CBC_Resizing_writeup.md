# **Writeup: CBC Bit-Flipping Attack with Variable-Length Plaintexts**

## **Challenge Overview**
This challenge builds on the previous CBC bit-flipping attack, but now we must modify an encrypted message to produce a plaintext of **different length**. The worker still decrypts tasks and checks commands, but we can no longer rely on the original and target messages having the same length.

### **Key Differences from Previous Challenge**
1. **Original message:** `"sleep"` (5 bytes)
2. **Target message:** Can now be **shorter or longer** (e.g., `"flag"` or `"get_flag"`)
3. **Padding becomes critical** since length changes affect PKCS#7 padding structure

## **Technical Background**

### **CBC Decryption Mechanics**
Recall that in CBC mode:
```
Plaintext₁ = Decrypt(Ciphertext₁) XOR IV
```
This means:
- Modifying the IV allows controlled changes to the first plaintext block
- Subsequent blocks depend on previous ciphertext blocks

### **PKCS#7 Padding Rules**
- Plaintext must be padded to a multiple of the block size (16 bytes for AES)
- Padding byte value equals the number of padding bytes (e.g., `\x0b` for 11 padding bytes)
- Worker uses `unpad()` which validates padding structure

## **Attack Strategy**

### **Case 1: Shorter Target Message (e.g., "sleep" → "flag")**
1. **Original padded plaintext:** `"sleep" + \x0b\x0b...\x0b` (16 bytes total)
2. **Target padded plaintext:** `"flag" + \x0c\x0c...\x0c` (16 bytes total)
3. **Compute modified IV:**
   ```
   modified_iv = original_iv XOR ("sleep" + 11*\x0b) XOR ("flag" + 12*\x0c)
   ```
4. **Worker processing:**
   - Decrypts to properly padded `"flag" + padding`
   - `unpad()` removes padding correctly
   - Sees command `"flag"`

### **Case 2: Longer Target Message (More Complex)**
If we need more space than the original message provided:
1. **Option A:** Use multi-block approach (if worker accepts it)
   - Requires controlling IV and first ciphertext block
2. **Option B:** Find a shorter command that triggers flag disclosure
   - Example: If worker accepts `"f"` as valid command
3. **Option C:** Corrupt padding strategically
   - May cause `unpad()` to fail but might reveal information

## **Step-by-Step Solution for "sleep" → "flag"**

1. **Capture original task:**
   ```
   TASK: <iv(16)> + <encrypted("sleep" + padding)>
   ```

2. **Calculate padding adjustments:**
   - Original padding: 11 bytes of `\x0b`
   - New padding: 12 bytes of `\x0c` (since "flag" is 4 bytes)

3. **Construct modified IV:**
   ```python
   original_padded = b"sleep" + b"\x0b"*11
   target_padded = b"flag" + b"\x0c"*12
   modified_iv = bytes([iv[i] ^ original_padded[i] ^ target_padded[i] for i in range(16)])
   ```

4. **Form malicious task:**
   ```
   TASK: <modified_iv_hex> + <original_ciphertext_hex>
   ```

5. **Worker processing:**
   - Decrypts to `"flag" + proper padding`
   - Successfully unpads to `"flag"`
   - Executes flag command

## **Key Insights**

1. **Padding Awareness:**
   - Must maintain valid PKCS#7 structure
   - Different length → different padding bytes

2. **Block Size Constraints:**
   - Single-block attacks are simplest
   - Multi-block requires more control

3. **Worker Behavior Matters:**
   - Some commands might work with partial matches
   - Error messages might leak information

## **Conclusion**

This challenge demonstrates that CBC bit-flipping attacks can work even when changing message lengths, provided we:
1. Carefully maintain valid padding structure
2. Understand how the worker processes decrypted messages
3. Calculate precise XOR adjustments for both message content and padding

The solution shows why cryptographic systems need both confidentiality AND integrity protection (e.g., HMAC) to prevent such tampering attacks.
