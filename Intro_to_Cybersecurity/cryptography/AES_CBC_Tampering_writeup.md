# **CBC Bit-Flipping Attack Writeup**  
**Challenge:** *Tampering with AES-CBC to Force Flag Disclosure*  

## **Understanding the Scenario**
We have two components:
1. **Dispatcher**: Encrypts the command `"sleep"` using **AES-CBC** and sends it as `TASK: <IV + ciphertext>`.
2. **Worker**: Decrypts the task, checks if the plaintext is `"sleep"` or `"flag!"`, and reveals the flag if the command is `"flag!"`.

### **Objective**  
Modify the encrypted task so that the worker decrypts it as `"flag!"` instead of `"sleep"` **without knowing the key**.

---

## **CBC Mode Vulnerability**
In **Cipher Block Chaining (CBC)**, the decryption of the first block is:  
```
Plaintext₁ = Decrypt(Ciphertext₁) XOR IV
```
This means:
- If we **modify the IV**, we can **control the first plaintext block** after decryption.
- The rest of the ciphertext remains unchanged.

---

## **Attack Strategy (Bit-Flipping)**
Since the worker checks for `"flag!"`, we need to manipulate the IV such that:  
```
Decrypt(Ciphertext₁) XOR Modified_IV = "flag!" (with padding)
```
But originally:  
```
Decrypt(Ciphertext₁) XOR Original_IV = "sleep" (with padding)
```
So, we can compute:  
```
Modified_IV = Original_IV XOR "sleep" XOR "flag!"
```
(Note: Both `"sleep"` and `"flag!"` are padded to 16 bytes using **PKCS#7**.)

### **Step-by-Step Exploit**
1. **Extract IV & Ciphertext**  
   - The dispatcher sends `TASK: <hex>`, where the first 16 bytes are the IV and the rest is ciphertext.

2. **Calculate Required XOR Adjustment**  
   - The plaintext `"sleep"` is padded to `b"sleep\x0b\x0b...\x0b"` (11 bytes of `0x0b`).  
   - We want it to decrypt as `b"flag!\x0b\x0b...\x0b"`.  
   - Compute:  
     ```
     Modified_IV = Original_IV XOR (b"sleep" + b"\x0b"*11) XOR (b"flag!" + b"\x0b"*11)
     ```
     (This flips the necessary bits in the IV to change `"sleep"` → `"flag!"`.)

3. **Construct Malicious Task**  
   - Replace the original IV with `Modified_IV` while keeping the ciphertext unchanged.  
   - Send:  
     ```
     TASK: <Modified_IV_hex> + <Original_Ciphertext_hex>
     ```

4. **Worker Decrypts Malicious Task**  
   - The worker decrypts it as `"flag!"` (due to the manipulated IV).  
   - Since the plaintext matches `"flag!"`, it prints the flag.  

---

## **Why This Works**
- **CBC’s malleability** allows us to alter the plaintext by modifying the IV.  
- The **padding remains valid** (since we preserved the structure).  
- The **worker does not validate integrity** (no MAC or signature checks).  

### **Impact**
- **Confidentiality is preserved** (we don’t recover the key).  
- **Integrity is broken** (we tampered with the message).  

---

## **Conclusion**
This challenge demonstrates a **CBC bit-flipping attack**, where an attacker can manipulate ciphertexts to produce controlled plaintext changes. The key takeaways:
1. **CBC alone does not guarantee integrity** (use **HMAC** or **AEAD** modes like AES-GCM).  
2. **Never trust ciphertexts without authentication** (tampering is possible).  
3. **Padding must be considered** (we preserved PKCS#7 to avoid errors).  

By flipping bits in the IV, we forced the worker to execute `"flag!"` instead of `"sleep"`, successfully leaking the flag. 🚩
