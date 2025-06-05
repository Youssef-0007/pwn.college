# One-Time Pad Tampering Challenge Writeup

## Understanding the Challenge

This challenge demonstrates a critical limitation of the One-Time Pad (OTP) encryption: while it provides perfect confidentiality, it offers no integrity protection. The system consists of two components:

1. **Dispatcher**: Generates encrypted commands using XOR with a secret key
2. **Worker**: Decrypts and executes received commands

The dispatcher is hardcoded to send the command "sleep", but we want to make the worker execute "flag!" instead to get the flag.

## Key Observations

1. **XOR Properties**:
   - XOR is malleable: modifying ciphertext affects plaintext in predictable ways
   - If `ciphertext = plaintext XOR key`, then `modified_ciphertext XOR key = modified_plaintext`

2. **System Behavior**:
   - Both processes use the same secret key
   - Dispatcher only sends "sleep" commands
   - Worker executes any properly encrypted command

## Attack Strategy

We can exploit XOR's malleability to:

1. Compute the difference between "sleep" and "flag!"
2. Apply this difference to the original ciphertext
3. Create a new ciphertext that decrypts to "flag!"

### Mathematical Representation

1. Original: `ciphertext = "sleep" XOR key`
2. Desired: `"flag!" XOR key`
3. Difference: `delta = "sleep" XOR "flag!"`
4. Malicious ciphertext: `ciphertext XOR delta = ("sleep" XOR key) XOR ("sleep" XOR "flag!") = "flag!" XOR key`

## Solution Steps

1. **Calculate Delta**:
   ```python
   delta = strxor(b"sleep", b"flag!")
   ```

2. **Intercept Original Ciphertext**:
   - Launch dispatcher process and read its output
   - Extract the hex-encoded ciphertext

3. **Create Malicious Ciphertext**:
   ```python
   malicious_ct = strxor(original_ct, delta)
   ```

4. **Send to Worker**:
   - Launch worker process
   - Send modified ciphertext as a new task

5. **Receive Flag**:
   - Worker decrypts to "flag!" and prints the flag

## Final Solution Code

```python
from pwn import *

def strxor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

# Calculate difference between commands
delta = strxor(b"sleep", b"flag!")

# Get original ciphertext from dispatcher
dispatcher = process('/challenge/dispatcher')
dispatcher.recvuntil(b'TASK: ')
original_ct = bytes.fromhex(dispatcher.recvline().strip().decode())
dispatcher.close()

# Create malicious ciphertext
malicious_ct = strxor(original_ct, delta)

# Send to worker
worker = process('/challenge/worker')
worker.sendline(b'TASK: ' + malicious_ct.hex().encode())

# Get flag
print(worker.recvall().decode())
```

## Why This Works

1. **Same Key**: Both processes use identical keys, allowing our modification
2. **XOR Malleability**: We can predictably alter plaintext by modifying ciphertext
3. **No Integrity Check**: Worker blindly executes any properly formatted command

## Key Takeaways

1. OTP provides confidentiality but no integrity
2. XOR's properties enable ciphertext manipulation
3. Real-world systems need authentication alongside encryption
4. Always validate command integrity in secure systems

