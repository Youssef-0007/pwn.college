# Many-Time Pad Attack Writeup: Exploiting Key Reuse with Null Bytes

## Introduction to the Vulnerability

This challenge demonstrates a catastrophic failure that occurs when a one-time pad (OTP) key is reused - a violation of the fundamental security requirement that OTP keys must be used exactly once. The service provides two critical capabilities:
1. It gives us the flag encrypted with a secret key
2. It allows us to encrypt arbitrary messages using the same key

## Core Insight: The Null Byte Exploit

The most straightforward and effective attack involves encrypting null bytes (all zeros). Here's why this works:

### XOR Cryptographic Identity Property

The fundamental mathematical property we exploit:
```
X ⊕ 0 = X (for any X)
```
Where ⊕ represents the XOR operation. This means any value XORed with zero remains unchanged.

### Applied to OTP Encryption

The encryption process follows:
```
Ciphertext = Plaintext ⊕ Key
```

When we encrypt null bytes (plaintext = 0):
```
Ciphertext = 0 ⊕ Key = Key
```

Therefore, by encrypting null bytes, the server effectively returns the key back to us!

## Step-by-Step Attack Process

1. **Capture the Encrypted Flag**
   - The service provides: `flag_encrypted = flag ⊕ key`

2. **Encrypt Null Bytes**
   - We send: `plaintext = \x00\x00\x00...` (length matching flag)
   - Server returns: `null_encrypted = null_bytes ⊕ key = key`

3. **Recover the Original Key**
   - We now have the key directly from step 2

4. **Decrypt the Flag**
   - Compute: `flag = flag_encrypted ⊕ key`

## Python Implementation

```python
from pwn import *
from Crypto.Util.strxor import strxor

def exploit():
    # Connect to the challenge
    conn = process('/challenge/run')
    
    # Step 1: Get encrypted flag
    conn.recvuntil(b'Flag Ciphertext (hex): ')
    flag_ct = bytes.fromhex(conn.recvline().strip().decode())
    
    # Step 2: Encrypt null bytes to get key
    null_plain = b'\x00' * len(flag_ct)
    conn.sendlineafter(b'Plaintext (hex): ', null_plain.hex())
    conn.recvuntil(b'Ciphertext (hex): ')
    null_ct = bytes.fromhex(conn.recvline().strip().decode())  # This is the key!
    
    # Step 3/4: Decrypt flag
    flag = strxor(flag_ct, null_ct)
    print(f"Recovered flag: {flag.decode()}")
    
    conn.close()

exploit()
```

## Why This Attack is Devastating

1. **Complete Key Recovery**: Unlike partial attacks, this gives us the full key
2. **Single Query Needed**: Only requires encrypting one carefully crafted message
3. **Universal Decryption**: The recovered key decrypts all messages using that key
4. **Theoretical Implications**: Demonstrates why OTP is only secure when used correctly

## Mitigation Strategies

1. **Never reuse OTP keys** - Each message needs fresh randomness
2. **Input validation** - Reject null bytes or other dangerous plaintexts
3. **Key rotation** - Ensure keys are only used once
4. **Authentication** - Add MACs to verify message integrity

## Conclusion

This attack beautifully illustrates how theoretical cryptographic security (OTP is provably secure when used correctly) completely breaks down when implementation requirements are violated. The null byte exploit serves as a powerful reminder that in cryptography, proper usage is just as important as strong algorithms.
