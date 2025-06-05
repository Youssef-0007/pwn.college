# **Writeup: Diffie-Hellman Key Exchange Challenge**

## **Challenge Overview**
This challenge involves performing a **Diffie-Hellman Key Exchange (DHKE)** with a server that provides fixed public parameters (`p`, `g`, `A`) and requires us to submit a valid public key `B` and compute the correct shared secret `s`. The goal is to derive `s` correctly to obtain the flag.

### **Given Parameters**
- A large **2048-bit prime `p`** (from RFC 3526).
- A generator `g = 2`.
- Alice’s public key `A = g^a mod p` (where `a` is a randomly generated private key).

### **Requirements**
1. Submit a public key `B` (in hex) such that `B > 2¹⁰²⁴`.
2. Compute the shared secret `s = B^a mod p` and submit it.
3. If `s` matches the server’s computation, the flag is revealed.

---

## **Approach**
Since we don’t know Alice’s private key `a`, we must choose `B` in a way that allows us to compute `s` without knowing `a`.

### **Key Insight**
We can choose `B` such that:
- `B = g^k mod p` for some known `k`.
- Then, the shared secret becomes:
  \[
  s = B^a \mod p = (g^k)^a \mod p = (g^a)^k \mod p = A^k \mod p
  \]
- Since we know `A` and can choose `k`, we can compute `s` directly.

### **Choosing `k`**
We need `B > 2¹⁰²⁴`. Since `g = 2`:
- The smallest `k` where `2^k > 2¹⁰²⁴` is `k = 1025`.
- Thus, `B = 2¹⁰²⁵` (which is `0x2` followed by 256 zeros in hex).

### **Computing `s`**
Using the chosen `B`:
\[
s = A^{1025} \mod p
\]

---

## **Solution Steps**
1. **Extract `p`, `g`, and `A`** from the server.
2. **Choose `B = 2¹⁰²⁵`** (ensuring `B > 2¹⁰²⁴`).
3. **Compute `s = pow(A, 1025, p)`** (since `s = A^k mod p`).
4. **Submit `B` and `s`** in hexadecimal format.
5. **Receive the flag** upon successful validation.

---

## **Automated Exploit Script**
```python
from pwn import *

# Connect to the challenge
conn = process('/challenge/run')

# Extract p, g, A
conn.recvuntil(b'p = ')
p = int(conn.recvline().strip(), 16)
conn.recvuntil(b'g = ')
g = int(conn.recvline().strip(), 16)
conn.recvuntil(b'A = ')
A = int(conn.recvline().strip(), 16)

# Choose B = 2^1025 (which is > 2^1024)
k = 1025
B = pow(2, k)

# Compute s = A^k mod p
s = pow(A, k, p)

# Send B and s in hex (without '0x' prefix)
conn.sendline(hex(B)[2:].encode())
conn.sendline(hex(s)[2:].encode())

# Get the flag
conn.interactive()
```

---

## **Why This Works**
- **Security Check Bypass**: `B = 2¹⁰²⁵` is large enough (`> 2¹⁰²⁴`), satisfying the server’s condition.
- **Shared Secret Calculation**: Since `B = g^k`, we compute `s = A^k mod p` without knowing `a`.
- **No Discrete Log Needed**: We avoid solving for `a` by choosing a `B` that simplifies the computation.

---

## **Mitigation (Real-World Scenario)**
In real-world DHKE:
- Both parties should **validate public keys** (e.g., ensure `1 < B < p-1`).
- Use **safe primes** (where `(p-1)/2` is also prime) to prevent subgroup attacks.
- Enforce **proper key derivation** (e.g., hashing `s` before use).

---

## **Conclusion**
This challenge demonstrates how **improper validation of public keys** can lead to trivial key recovery. By choosing `B` strategically, we bypass the need to solve the discrete logarithm problem and compute `s` directly.
