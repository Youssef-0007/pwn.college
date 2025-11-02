# **"Does It Buzz" Pwn Challenge Write-Up**

## **Challenge Overview**
A sophisticated binary exploitation challenge with multiple security protections including **Stack Canary**, **PIE**, **NX**, and control-flow integrity features. The challenge requires bypassing modern protections to achieve arbitrary code execution.

## **Protection Analysis**
- **Stack Canary**: Prevents stack buffer overflow attacks
- **PIE**: Randomizes binary base address  
- **NX**: Makes stack non-executable
- **Partial RELRO**: GOT is writable but not read-only
- **SHSTK/IBT**: Advanced control-flow integrity

## **Vulnerability Analysis**

### **Primary Vulnerability**
The challenge contains a controlled `strcpy` operation with attacker-influenced pointers:

```c
read(0, local_64, 0x58);        // 88-byte read into 56-byte buffer
strcpy((char *)local_18, local_20);  // Controlled strcpy
```

**Key Insight**: While the buffer overflow is limited (88 bytes into 56-byte buffer), the critical vulnerability lies in controlling the `strcpy` source and destination pointers (`local_20` and `local_18`).

### **Constraints**
- **Limited overflow**: Only 32 bytes beyond buffer (88 - 56 = 32)
- **Canary protection**: Cannot overwrite return address directly
- **NX**: No shellcode execution on stack

## **Exploitation Strategy**

### **Phase 1: Information Gathering & Address Leakage**

#### **Step 1: FizzBuzz Address Leak**
```python
first_payload = b"A" * 64 + p32(0xfffffff5)
```
- Overflows buffer and sets loop counter to -11 (signed)
- Triggers FizzBuzz path where `local_20 = &fuzzbuzz`
- Leaks binary base address through "Correct answer: FizzBuzz" output

#### **Step 2: Stack Address Leak**  
```python
second_payload = b"B" * 64 + p32(0xfffffff5)
```
- Triggers Buzz path where `local_20 = local_2c` (stack address)
- Leaks stack layout information

### **Phase 2: GOT Overwrite via Controlled strcpy**

#### **Key Calculations**
From leaked addresses:
- **Binary Base**: Derived from `fizzbuzz_address_value`
- **strcpy@GOT**: `fizzbuzz_address_value - 0x70`
- **win() function**: `fizzbuzz_address_value - 0x2dcf`

#### **The Exploit Payload**
```python
exploitation_payload = b"C" * 56
exploitation_payload += p64(fizzbuzz_address_value - 0x2dcf)  # win() address in local_2c
exploitation_payload += p32(0xfffffff6)                       # Loop counter
exploitation_payload += p64(local_2c_address_value)           # local_20 -> &local_2c (source)
exploitation_payload += p64(fizzbuzz_address_value - 0x70)    # local_18 -> strcpy@GOT (destination)
```

### **Phase 3: Arbitrary Write Primitive**

The exploit sets up a controlled memory write:
```
strcpy(strcpy@GOT, win_function_address)
```

**What happens**:
1. `local_18` points to `strcpy@GOT` entry
2. `local_20` points to `local_2c` which contains `win()` function address  
3. `strcpy` overwrites `strcpy@GOT` with `win()` address
4. Next `strcpy` call executes `win()` function instead

## **Technical Details**

### **Bypassing PIE**
- Used leaked `fizzbuzz` address to calculate binary base
- Calculated offsets to `strcpy@GOT` and `win()` function
- **Offset calculations**:
  - `strcpy@GOT` = `fizzbuzz_address - 0x70`
  - `win()` = `fizzbuzz_address - 0x2dcf`

### **Bypassing Stack Canary**
- Limited overflow to only overwrite `local_18` and `local_20`
- Never touched canary at `rbp-0x10`
- Used existing stack variables as pointer sources

### **Bypassing NX**
- No shellcode execution needed
- Reused existing `win()` function in binary
- GOT overwrite redirects control flow to legitimate code

### **Loop Counter Manipulation**
```python
p32(0xfffffff5)  # -11 signed
p32(0xfffffff6)  # -10 signed  
```
- Maintained loop execution for multiple stages
- Ensured divisible-by-15 and divisible-by-5 conditions for specific code paths

## **The Win Condition**

### **Final Execution Flow**
1. **GOT overwrite**: `strcpy@GOT` → `win()` address
2. **Function call**: Next `strcpy` call executes `win()`
3. **Flag retrieval**: `win()` function reads and displays flag

### **Triggering the Win**
```python
p.send(b"flag")  # next message to trigger the strcpy
```

## **Key Innovations**

### **1. Pointer Source Reuse**
Used `local_2c` (the Buzz string location) as both:
- **Leaked stack address** for calculations
- **Storage location** for `win()` function address

### **2. GOT Hijacking**
Instead of traditional return address overwrite, hijacked `strcpy@GOT` to:
- Bypass stack canary protection
- Leverage the very vulnerability for exploitation
- Achieve clean control flow redirection

### **3. Multi-Stage Payload**
Carefully staged exploitation across multiple loop iterations:
- Stage 1: Address leakage
- Stage 2: Stack analysis  
- Stage 3: GOT overwrite
- Stage 4: Function triggering

## **Mitigation Bypass Summary**

| Protection | Bypass Method |
|------------|---------------|
| **PIE** | Address leakage via FizzBuzz string |
| **Stack Canary** | Limited overflow, never reach canary |
| **NX** | Reuse existing `win()` function |
| **Partial RELRO** | GOT overwrite attack |
| **Control-Flow Integrity** | Legitimate control transfer via GOT |

## **Conclusion**

This challenge demonstrates sophisticated exploitation techniques in a modern protected environment. The solution showcases:

1. **Precise memory layout understanding** through careful offset calculations
2. **Creative use of existing program features** (FizzBuzz logic) for information leakage
3. **GOT overwrite as a powerful primitive** when stack-based attacks are mitigated
4. **Multi-stage exploitation** to gradually build control despite constraints

The exploit successfully chains limited memory corruption with program logic manipulation to achieve arbitrary code execution, bypassing multiple state-of-the-art security protections.

---

This write-up captures the technical sophistication of your solution and can be used for documentation, competition submissions, or educational purposes. Excellent work on solving this advanced challenge!
