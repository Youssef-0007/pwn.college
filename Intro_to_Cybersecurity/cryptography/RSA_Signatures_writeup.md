# RSA Signature Attack - Challenge Writeup

## Challenge Overview

This challenge explores a fundamental vulnerability in textbook RSA signatures: the multiplicative property that allows attackers to forge signatures for messages they've never directly signed.

**Goal**: Obtain the flag by exploiting RSA signature properties to bypass the signing oracle's restrictions.

## Challenge Analysis

### Given Files
- `dispatcher`: Signing oracle that creates RSA signatures but refuses to sign anything containing "flag"
- `worker`: Signature verification system that executes commands if properly signed
- `key-n`, `key-e`: Public RSA key components
- `key-d`: Private key (access denied)

### Key Restrictions
- The dispatcher won't sign any message containing the string "flag"
- The worker only executes the "flag" command to reveal the flag
- We need a valid RSA signature for "flag" without directly signing it

## The Vulnerability

The challenge exploits the **multiplicative property** of RSA signatures:

```
If sig₁ = m₁^d mod n and sig₂ = m₂^d mod n
Then (sig₁ × sig₂) mod n = (m₁ × m₂)^d mod n
```

This means if we can find two factors `f₁` and `f₂` such that `f₁ × f₂ = "flag"` (as integers), we can:
1. Get signatures for `f₁` and `f₂` separately
2. Multiply those signatures to get a valid signature for "flag"

## Solution Approach

### Step 1: Convert "flag" to Integer
```python
target = b"flag"
target_int = int.from_bytes(target, "little")  # 1734437990
```

### Step 2: Find Factors
The integer 1734437990 is even, so we can factor it as:
- `factor1 = 2`
- `factor2 = 1734437990 // 2 = 867218995`

### Step 3: Verify Safety
Convert factors back to bytes and ensure neither contains "flag":
```python
factor1_bytes = factor1.to_bytes(256, "little").rstrip(b"\x00")  # b'\x02'
factor2_bytes = factor2.to_bytes(256, "little").rstrip(b"\x00")  # b'3\x01\xb1\x03'
```

Neither contains "flag", so we're safe to proceed.

### Step 4: Get Individual Signatures
```bash
# Sign factor 1
./dispatcher $(echo -n "Ag==" | base64 -d | base64)  # \x02 encoded

# Sign factor 2  
./dispatcher $(echo -n "MwGxAw==" | base64 -d | base64)  # factor2 encoded
```

### Step 5: Combine Signatures
```python
# Read modulus n
n = int(open("/challenge/key-n").read(), 16)

# Decode signatures
sig1_int = int.from_bytes(base64.b64decode(sig1_b64), "little")
sig2_int = int.from_bytes(base64.b64decode(sig2_b64), "little")

# Apply multiplicative property
combined_sig_int = (sig1_int * sig2_int) % n

# Convert back to base64
combined_sig_b64 = base64.b64encode(combined_sig_int.to_bytes(256, "little")).decode()
```

### Step 6: Execute Attack
```bash
./worker [combined_signature_b64]
```

## Complete Solution

```python
#!/usr/bin/env python3
import base64
import subprocess

def main():
    # Step 1: Convert "flag" to integer and find factors
    target = b"flag"
    target_int = int.from_bytes(target, "little")
    
    # Factor the integer (it's even, so divide by 2)
    factor1 = 2
    factor2 = target_int // 2
    
    # Step 2: Convert factors to bytes and base64
    factor1_bytes = factor1.to_bytes(256, "little").rstrip(b"\x00")
    factor2_bytes = factor2.to_bytes(256, "little").rstrip(b"\x00")
    
    factor1_b64 = base64.b64encode(factor1_bytes).decode()
    factor2_b64 = base64.b64encode(factor2_bytes).decode()
    
    # Step 3: Get signatures from dispatcher
    result1 = subprocess.run(["/challenge/dispatcher", factor1_b64], 
                           capture_output=True, text=True)
    result2 = subprocess.run(["/challenge/dispatcher", factor2_b64], 
                           capture_output=True, text=True)
    
    # Extract signatures
    sig1_b64 = result1.stdout.split("Signed command (b64): ")[1].strip()
    sig2_b64 = result2.stdout.split("Signed command (b64): ")[1].strip()
    
    # Step 4: Combine signatures using multiplicative property
    n = int(open("/challenge/key-n").read(), 16)
    
    sig1_int = int.from_bytes(base64.b64decode(sig1_b64), "little")
    sig2_int = int.from_bytes(base64.b64decode(sig2_b64), "little")
    
    combined_sig_int = (sig1_int * sig2_int) % n
    combined_sig_b64 = base64.b64encode(combined_sig_int.to_bytes(256, "little")).decode()
    
    # Step 5: Submit to worker
    result3 = subprocess.run(["/challenge/worker", combined_sig_b64], 
                           capture_output=True, text=True)
    print(result3.stdout)

if __name__ == "__main__":
    main()
```

## Mathematical Explanation

The attack works because RSA signatures are **multiplicatively homomorphic**:

1. **Signing**: `sig = m^d mod n`
2. **Verification**: `m = sig^e mod n`
3. **Multiplicative Property**: `(m₁^d × m₂^d) mod n = (m₁ × m₂)^d mod n`

When we multiply two signatures, we get a valid signature for the product of the original messages.

## Why This Works

- `dispatcher` signs `factor1` → `sig1 = factor1^d mod n`
- `dispatcher` signs `factor2` → `sig2 = factor2^d mod n`
- We compute `combined_sig = (sig1 × sig2) mod n`
- This equals `(factor1 × factor2)^d mod n = "flag"^d mod n`
- `worker` verifies: `combined_sig^e mod n = "flag"`

## Mitigations

This attack is prevented in practice by:

1. **Padding Schemes**: RSA-PSS adds randomness that breaks the multiplicative property
2. **Message Hashing**: Sign `H(message)` instead of the message directly
3. **Structured Signatures**: Use formats that prevent factorization attacks

## Key Takeaways

- Textbook RSA is vulnerable to multiplicative attacks
- Never use raw RSA for signatures in production
- Proper padding schemes are essential for security
- Mathematical properties can be exploited in unexpected ways

## Flag
Running the solution reveals the flag, demonstrating successful exploitation of the RSA signature vulnerability.
