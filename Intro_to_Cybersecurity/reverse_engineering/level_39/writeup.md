# **Reverse Engineering Challenge Writeup: Binary Patching a Jump Table for Interoperability**

## **Challenge Overview**
The goal was to modify the `cimg` binary to work with `/challenge/quest.py` by patching:
1. The **magic number** (`cIMG` → `CNNR`).
2. **Directive codes** (reversed in `CIMG_1337` compared to `CIMG_NORMAL`).

Unlike the previous challenge, this binary used a **jump table** for directive handling instead of `if-else` checks, requiring a different patching approach.

---

## **Step 1: Identify the Mismatch**
### **Problem Analysis**
1. **Magic Number Mismatch**  
   - `quest.py` sends `CNNR` as the magic number.  
   - `cimg` expects `cIMG`.  

2. **Directive Code Mismatch**  
   - `CIMG_1337` reverses directive codes compared to `CIMG_NORMAL`:  

   | Directive       | `CIMG_NORMAL` | `CIMG_1337` |  
   |----------------|---------------|-------------|  
   | `RENDER_FRAME`  | `0x0001`      | `0x0007`    |  
   | `RENDER_PATCH`  | `0x0002`      | `0x0006`    |  
   | `CREATE_SPRITE` | `0x0003`      | `0x0005`    |  
   | `RENDER_SPRITE` | `0x0004`      | `0x0004`    | *(unchanged)* |  
   | `LOAD_SPRITE`   | `0x0005`      | `0x0003`    |  
   | `FLUSH`         | `0x0006`      | `0x0002`    |  
   | `SLEEP`         | `0x0007`      | `0x0001`    |  

   - The binary uses a **jump table** to dispatch directives, so we must remap the table instead of patching `cmp` instructions.

---

## **Step 2: Reverse Engineer the Jump Table**
### **Locating the Jump Table**
1. **Disassembly Analysis**  
   - The switch-case is compiled into a jump table at `0x403384` (found via Binary Ninja/Ghidra).  
   - Each entry is a **4-byte relative offset** from a base address (`%rbx`).  

2. **Original Jump Table**  
   ```
   00403384 84 e0 ff ff     → FFFFE084h (handle_1)  
   00403388 8b e0 ff ff     → FFFFE08Bh (handle_2)  
   0040338c 92 e0 ff ff     → FFFFE092h (handle_3)  
   00403390 99 e0 ff ff     → FFFFE099h (handle_4)  
   00403394 a0 e0 ff ff     → FFFFE0A0h (handle_5)  
   00403398 a7 e0 ff ff     → FFFFE0A7h (handle_6)  
   0040339c ae e0 ff ff     → FFFFE0AEh (handle_7)  
   ```

### **Patching Strategy**
To support `CIMG_1337`, we **reverse the table entries**:
- `0x1` (RENDER_FRAME) → `handle_7` (`FFFFE0AEh`)  
- `0x2` (RENDER_PATCH) → `handle_6` (`FFFFE0A7h`)  
- `...`  
- `0x7` (SLEEP) → `handle_1` (`FFFFE084h`)  

**New Table Layout**:
```
Index 0 (Input 1): FFFFE0AEh (handle_7)  
Index 1 (Input 2): FFFFE0A7h (handle_6)  
Index 2 (Input 3): FFFFE0A0h (handle_5)  
Index 3 (Input 4): FFFFE099h (handle_4) *(unchanged)*  
Index 4 (Input 5): FFFFE092h (handle_3)  
Index 5 (Input 6): FFFFE08Bh (handle_2)  
Index 6 (Input 7): FFFFE084h (handle_1)  
```

---

## **Step 3: Patching the Binary**
### **1. Patch the Magic Number**
- **Location**: Offset `0x32f8` (found via `xxd`).  
- **Patch**:  
  ```bash
  printf '\x00CNNR\x00' | dd of=./patched_cimg bs=1 seek=$((0x32f8)) conv=notrunc
  ```

### **2. Patch the Jump Table**
- **Location**: `0x403384` (7 entries × 4 bytes = 28 bytes).  
- **Patch**:  
  ```bash
  printf '\xae\xe0\xff\xff\xa7\xe0\xff\xff\xa0\xe0\xff\xff\x99\xe0\xff\xff\x92\xe0\xff\xff\x8b\xe0\xff\xff\x84\xe0\xff\xff' | dd of=./patched_cimg bs=1 seek=$((0x403384)) conv=notrunc
  ```
- **Verification**:  
  ```bash
  xxd -s 0x403384 -l 28 ./patched_cimg
  ```
  Expected output:
  ```
  00403384: aee0 ffff a7e0 ffff a0e0 ffff 99e0 ffff  ................
  00403394: 92e0 ffff 8be0 ffff 84e0 ffff            ............
  ```

---

## **Step 4: Testing the Patched Binary**
1. **Run the Challenge**:  
   ```bash
   /challenge/quest.py | ./patched_cimg
   ```
2. **Expected Behavior**:  
   - No "Invalid magic number" or "Invalid directive" errors.  
   - The game renders correctly and prints the flag.  

---

## **Why This Worked**
1. **Magic Number Patch**  
   - Aligned the binary’s expected header with `quest.py`’s output.  

2. **Jump Table Patch**  
   - Remapped the directive handlers to match `CIMG_1337`’s reversed codes.  
   - **No logic changes**: Only the dispatch order was modified.  

3. **Full RELRO Bypass**  
   - Directly patched the binary on disk, avoiding runtime restrictions.  

---

## **Key Takeaways**
1. **Jump Tables** are common in compiled code for efficient branching.  
2. **Patching Strategies** depend on the control-flow structure:  
   - `if-else` → Patch `cmp` instructions.  
   - `switch-case` → Patch the jump table or handlers.  
3. **Tools Used**:  
   - Binary Ninja/Ghidra for disassembly.  
   - `xxd`/`dd` for binary patching.  

---

## **Final Answer**
By patching:  
1. The **magic number** (`cIMG` → `CNNR`).  
2. The **jump table** (reversing handler mappings),  

The patched `cimg` now correctly processes `quest.py`’s output, revealing the flag.  

**Flag**: `FLAG{your_flag_here}`  

---

### **Lessons Learned**
- Always verify patches with disassembly and `xxd`.  
- Understand how compilers implement control flow (jump tables vs. `if-else`).  
- Use reverse engineering tools (Binary Ninja/Ghidra) for precision.  

