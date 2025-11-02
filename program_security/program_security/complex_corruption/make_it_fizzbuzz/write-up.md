# **Make-It-FizzBuzz Challenge Write-Up**

## **Challenge Overview**
"Make-It-FizzBuzz" is a sophisticated binary exploitation challenge that combines memory corruption techniques with the classic FizzBuzz game logic. The challenge features multiple security protections including **Stack Canary**, **PIE**, and **NX**, requiring a multi-stage exploitation approach.

## **Security Protections**
- **PIE**: Address Space Layout Randomization
- **Stack Canary**: Stack overflow detection
- **NX**: No-Execute stack protection
- **Partial RELRO**: GOT is writable

## **Vulnerability Analysis**

### **Primary Vulnerability: Controlled strcpy**
The challenge contains a critical vulnerability in the FizzBuzz loop:

```c
read(0, local_48 + 4, 0x54);        // 84-byte read into limited buffer
strcpy(local_20, local_28);         // Both pointers controllable via overflow
```

**Key Insight**: While the buffer overflow is limited, attackers can control both the source (`local_28`) and destination (`local_20`) pointers of the `strcpy` operation.

### **Memory Layout**
```
rbp-0x44: Input buffer (local_48 + 4)
rbp-0x28: local_28 (strcpy source pointer)
rbp-0x20: local_20 (strcpy destination pointer)
rbp-0x10: Stack Canary
```

## **Exploitation Strategy**

The solution employs a sophisticated **four-stage exploitation** approach:

### **Stage 1: Information Leakage**
**Objective**: Leak binary base address via FizzBuzz string
```python
first_payload = b"A" * 24 + p32(0xfffffff5)
```
- Overflows buffer to reach `local_28` pointer
- Sets loop counter to maintain execution
- Leaks `fuzzbuzz` address from binary's .bss section

### **Stage 2: Stack Address Leakage**  
**Objective**: Leak stack address for pointer calculations
```python
second_payload = b"B" * 24 + p32(0xfffffff5)
```
- Uses Buzz path where `local_28 = &local_38 + 4`
- Leaks stack address of `local_38` for future calculations

### **Stage 3: Return Address Preparation**
**Objective**: Prepare stack for shellcode execution
```python
ret_addr_payload = b"C" * 16 + p64(local_38_address_value - 0xf)
```
- Calculates buffer address for shellcode placement
- Sets up pointer overwrites for return address manipulation
- Uses precise offset calculations from leaked addresses

### **Stage 4: GOT Overwrite & Shellcode Execution**
**Objective**: Bypass NX and execute shellcode
```python
exploitation_payload = shellcode + padding + p64(mprotect_stack_addr)
```
- Places shellcode in buffer
- Overwrites `strcpy@GOT` with `mprotect_stack` address
- Makes stack executable on next strcpy call
- Executes shellcode to read flag

## **Key Technical Innovations**

### **1. mprotect_stack Function Exploitation**
The binary includes a built-in `mprotect_stack()` function that makes stack pages executable:
```c
void mprotect_stack(void) {
    void *stack_page = (void*)((ulong)&local_1d & 0xfffffffffffff000);
    mprotect(stack_page, 0x1000, 7);  // RWX permissions
}
```

### **2. Precise Offset Calculations**
The exploit uses mathematical calculations from leaked addresses:
- Binary base: `fizzbuzz_address_value - 0x4080`
- mprotect_stack: `fizzbuzz_address_value - 0x2e17` 
- strcpy@GOT: `fizzbuzz_address_value - 0x60`

### **3. Multi-Stage Pointer Control**
Each stage carefully manipulates different pointers:
- Stage 1-2: Information gathering
- Stage 3: Stack preparation  
- Stage 4: GOT overwrite and code execution

## **Bypassing Protections**

### **PIE Bypass**
- Leaked `fuzzbuzz` address provides binary base
- All subsequent addresses calculated from base

### **NX Bypass**
- Used built-in `mprotect_stack()` instead of libc
- No ROP chains required
- Pure memory corruption approach

### **Stack Canary Bypass**
- Limited overflow never reaches canary
- Strategic pointer manipulation avoids detection

## **Shellcode Design**
The challenge uses position-independent shellcode that:
- Opens and reads the "flag" file
- Outputs the contents
- Minimal size to fit in constrained buffer

## **Why This Solution Works**

1. **Leverages Program Logic**: Uses FizzBuzz paths for information leakage
2. **Precise Memory Manipulation**: Calculated offsets enable reliable exploitation
3. **Built-in Tools**: Reuses `mprotect_stack()` instead of external dependencies
4. **Gradual Escalation**: Multi-stage approach bypasses individual protections

## **Key Takeaways**

- **Memory corruption** can bypass modern protections when combined with program logic
- **Information leakage** is crucial for ASLR/PIE bypass
- **Built-in functions** can provide unexpected exploitation primitives
- **Multi-stage exploits** can overcome individual protection mechanisms

This challenge demonstrates that even with multiple security protections, creative exploitation techniques can achieve code execution through careful memory manipulation and program logic analysis.
