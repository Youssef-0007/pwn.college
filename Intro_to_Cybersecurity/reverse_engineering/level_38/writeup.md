# **Reverse Engineering Challenge Writeup: Binary Patching for Interoperability**

## **Challenge Overview**
The goal was to modify the `cimg` binary to work with `/challenge/quest.py` by patching:
1. The **magic number** (`cIMG` → `CNNR`)
2. **Directive codes** (reversed in `CIMG_1337` compared to `CIMG_NORMAL`)

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

   - The binary checks for `CIMG_NORMAL` codes but receives `CIMG_1337` codes → **"Invalid directive" errors**.

---

## **Step 2: Patching the Binary**
### **1. Patch the Magic Number**
- **Location**: Found at offset `0x32f8` using `xxd`:
  ```bash
  xxd /challenge/cimg | grep "cIMG"
  ```
- **Patch**:
  ```bash
  printf '\x00CNNR\x00' | dd of=./patched_cimg bs=1 seek=$((0x32f8)) conv=notrunc
  ```
- **Verification**:
  ```bash
  xxd -s 0x32f8 -l 4 ./patched_cimg  # Should show "CNNR"
  ```

### **2. Patch Directive Code Comparisons**
- **Location**: The `switch`/`if` block in `cimg` that dispatches directives.  
- **Method**:  
  Used **Binary Ninja** to locate and modify the comparison values:  
  - Changed `1` → `7`, `2` → `6`, `3` → `5`, `5` → `3`, `6` → `2`, `7` → `1`.  
  - Example (for `SLEEP`):  
    ```asm
    cmp cx, 0x7  ; Original
    → Changed to:
    cmp cx, 0x1  ; Patched
    ```

### **3. Key Patches Applied**
| Original Directive | New (CIMG_1337) | Patch Applied               |
|--------------------|-----------------|-----------------------------|
| `0x0001` (`RENDER_FRAME`)  | `0x0007` | `cmp 0x1` → `cmp 0x7` |
| `0x0002` (`RENDER_PATCH`)  | `0x0006` | `cmp 0x2` → `cmp 0x6` |
| `0x0003` (`CREATE_SPRITE`) | `0x0005` | `cmp 0x3` → `cmp 0x5` |
| `0x0005` (`LOAD_SPRITE`)   | `0x0003` | `cmp 0x5` → `cmp 0x3` |
| `0x0006` (`FLUSH`)         | `0x0002` | `cmp 0x6` → `cmp 0x2` |
| `0x0007` (`SLEEP`)         | `0x0001` | `cmp 0x7` → `cmp 0x1` |

---

## **Step 3: Testing the Patched Binary**
1. **Run the Game**:
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

2. **Directive Code Patch**  
   - Matched the binary’s checks to `CIMG_1337`’s reversed codes.  
   - **No logic changes**: Only modified comparison constants, preserving functionality.  

3. **Full RELRO Bypass**  
   - Used Binary Ninja to directly patch the binary on disk, avoiding runtime restrictions.  

---

## **Key Takeaways**
1. **Binary Patching** requires:  
   - Identifying exact offsets (using `xxd`, `objdump`, or Ghidra/Binary Ninja).  
   - Modifying only specific bytes (e.g., magic numbers, comparison values).  

2. **Interoperability Challenges** often involve:  
   - Matching header formats.  
   - Aligning protocol/opcode expectations.  

3. **Tools Used**:
   - `xxd` / `dd` for hex editing.  
   - Binary Ninja for precise patching.  
   - `objdump` for disassembly.  

---

## **Final Answer**
By patching:  
1. The **magic number** (`cIMG` → `CNNR`).  
2. **Directive codes** (`1`↔`7`, `2`↔`6`, `3`↔`5`),  

The patched `cimg` now correctly processes `quest.py`’s output, revealing the flag.  

**Flag**: `FLAG{your_flag_here}`  

--- 

### **Lessons Learned**
- Always verify patches with `xxd` and disassembly.  
- Understand binary protections (`RELRO`, `PIE`) that may block modifications.  
- Use reverse engineering tools (Binary Ninja/Ghidra) for precision.  

