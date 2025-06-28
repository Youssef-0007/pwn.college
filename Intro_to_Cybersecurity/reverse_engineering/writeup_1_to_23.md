### **Reverse Engineering Challenge Write-Up from level 1 to 23: cIMG File Format Analysis**

#### **Overview**
We solved a series of challenges involving the `cIMG` image format, progressing from basic file structure analysis to advanced reverse engineering of x86 binaries. Each challenge built upon the previous one, introducing new complexities.

---

## **Challenge Progression**

### **1. Magic Number Identification (Python)**
**Tools Used**: 
- `strings`, `xxd`, Python file operations

**Steps:**
1. Located magic number `"(~m6"` using `strings`
2. Created a file with the magic number:
   ```bash
   echo -ne '(~m6' > solution.cimg
   ```

**Key Learnings:**
- File formats often start with magic numbers
- Basic binary file creation with exact byte sequences

---

### **2. Versioned File Format (C Source)**
**Tools Used**: 
- Source code analysis, `struct.pack` in Python

**Steps:**
1. Identified header structure from source:
   - Magic: `"cIMG"`
   - Version: `1` (4-byte int)
   - Width/height: 4 bytes total
2. Created valid file:
   ```python
   header = b"cIMG" + struct.pack("<I", 1) + b"\x2e\x14"
   ```

**Key Learnings:**
- Mixed data types in binary headers
- Importance of byte ordering (endianness)

---

### **3. Dimension Validation (Python)**
**Tools Used**: 
- Python struct module, dynamic file generation

**Steps:**
1. Determined dimensions from asserts:
   ```python
   assert width == 79, height == 24
   ```
2. Generated pixel data:
   ```python
   data = b"A"*275 + b" "*(79*24 - 275)
   ```

**Key Learnings:**
- File formats often combine metadata and data sections
- Need to satisfy multiple constraints simultaneously

---

### **4. Color Pixel Format (x86 Binary)**
**Tools Used**: 
- IDA Pro, GDB, Python struct

**Steps:**
1. Reverse engineered header:
   ```c
   struct {
       char magic[4];    // "cIMG"
       uint16_t version; // 2
       uint8_t width;    // 4
       uint8_t height;   // 1
   }
   ```
2. Extracted RGB values from `desired_output` string
3. Created 4-pixel image:
   ```python
   pixels = [
       (170,54,112,ord('c')), 
       (161,129,204,ord('I')),
       ...
   ]
   ```

**Key Learnings:**
- Combining static (IDA) and dynamic (GDB) analysis
- Interpreting complex data structures from binaries
- Matching exact output requirements

---

## **Core Techniques Mastered**

### **1. Static Analysis**
- **IDA Pro**:
  - Decompilation (F5) to get pseudo-C
  - Cross-referencing (Xrefs) to trace data flow
  - String analysis (Shift+F12)

### **2. Dynamic Analysis**
- **GDB**:
  ```bash
  break *main+0x50   # Set breakpoints
  run ./input.cimg   # Test inputs
  x/10bx $rdi        # Examine memory
  ```
  - Verifying hypotheses from static analysis
  - Watching register/memory changes

### **3. Binary Crafting**
- **Python Struct**:
  ```python
  struct.pack("<I", 1234)  # 4-byte little-endian
  struct.pack("BBBB", *pixel)  # Pack RGBA values
  ```
- Precise byte-level file construction

### **4. Pattern Recognition**
- Magic numbers → File identification
- Header/body separation → Common in formats
- Size fields → Often precede data blocks

---

## **Key Insights**

1. **Validation Layers**:
   - Magic → Version → Dimensions → Content
   - Each layer must pass for success

2. **Debugging Approach**:
   ```mermaid
   graph LR
   A[Static Analysis] --> B[Form Hypothesis]
   B --> C[Dynamic Testing]
   C --> D[Adjust Hypothesis]
   D --> B
   ```

3. **Tool Synergy**:
   - IDA reveals structure
   - GDB confirms behavior
   - Python implements solution

---

## **Conclusion**
This series taught us to:
1. Work from simple to complex validation
2. Combine multiple analysis techniques
3. Appreciate how file formats encode metadata
4. Develop systematic reverse engineering workflows

The skills scale to analyzing real-world formats like PNG, ZIP, or malware samples. Each challenge reinforced that binary analysis requires both precision (exact byte values) and flexibility (adjusting approaches based on findings).
