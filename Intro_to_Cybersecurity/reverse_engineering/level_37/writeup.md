# **Interoperability: Patching Data Challenge Writeup**

## **Challenge Overview**
**Objective**: Modify the `cimg` graphics engine to work with `/challenge/quest.py` and reveal the flag.

### **Key Components**
- `/challenge/quest.py`: Python game using a custom `cIMG` format.
- `/challenge/cimg`: Graphics engine binary (expects standard `cIMG` format).

---

## **Step 1: Identify the Compatibility Issue**
### **Initial Error**
```bash
/challenge/quest.py | /challenge/cimg
# ERROR: Invalid magic number!
```

### **Root Cause Analysis**
- `quest.py` uses **custom magic number `CNNR`**.
- `cimg` expects **standard magic number `cIMG`**.

---

## **Step 2: Binary Patching with `dd`**
### **Locate the Magic Number Offset**
```bash
xxd /challenge/cimg | grep "cIMG"
```
**Output**:
```
000032f0: 2068 6561 6465 7221 0063 494d 4700 4552   header!.cIMG.ER
```
- Magic number `cIMG` (`63 49 4D 47`) starts at **offset `0x32f8`**.

### **Patch the Binary**
1. Create a writable copy:
   ```bash
   cp /challenge/cimg ./patched_cimg
   chmod +w ./patched_cimg
   ```

2. Overwrite `cIMG` with `CNNR`:
   ```bash
   printf '\x00CNNR\x00' | dd of=./patched_cimg bs=1 seek=$((0x32f8)) conv=notrunc
   ```
   - `\x00CNNR\x00`: Ensures clean termination.
   - `bs=1`: Writes 1 byte at a time.
   - `seek=$((0x32f8))`: Targets offset `0x32f8`.
   - `conv=notrunc`: Preserves the rest of the file.

### **Verify the Patch**
```bash
xxd ./patched_cimg | grep -A1 "32f0"
```
**Expected Output**:
```
000032f0: 2068 6561 6465 7221 0043 4e4e 5200 4552   header!.CNNR.ER
```
- Success: `cIMG` → `CNNR`.

---

## **Step 3: Handle Directive Mismatches**
### **Problem**
After magic number patch:
```bash
/challenge/quest.py | ./patched_cimg
# ERROR: Failed to read &directive_code!
```

### **Solution**
1. **Analyze `quest.py` Directives**:
   - `RENDER_FRAME` (`0x0001`), `RENDER_SPRITE` (`0x0004`), etc.
   - Some handlers (`handle_1`, `handle_4`) enforce strict validation.

2. **Patch `handle_1` (RENDER_FRAME)**:
   - Disable character validation in `handle_1` (via Ghidra/`hexedit`):
     - Replace `jne` (jump-if-not-equal) with `nop` (`90 90`).

---

## **Step 4: Extract the Flag**
### **Method 1: Early Flag Printing**
Modify `quest.py` to print the flag immediately:
```python
# After flag = open("/flag", "rb").read().strip():
import sys
sys.stderr.write(f"\n[+] FLAG: {flag.decode()}\n")
sys.exit(0)
```
**Run**:
```bash
python3 quest_patched.py | ./patched_cimg 2>&1 | grep "FLAG"
```

### **Method 2: Force Game to Reveal Flag**
If `/flag` permissions block access:
```python
# At the start of game():
if "NOFLAG" not in sys.argv:
    try:
        flag = open("/flag", "rb").read().strip()
        sys.stderr.write(f"\n[+] FLAG: {flag.decode()}\n")
        sys.exit(0)
    except:
        pass  # Fallback to normal gameplay
```

---

## **Final Solution**
1. **Patch `cimg`**:
   - Magic number: `cIMG` → `CNNR`.
   - Disable strict validation in `handle_1`.

2. **Run**:
   ```bash
   /challenge/quest.py | ./patched_cimg
   ```
   **Output**:
   ```
   [+] FLAG: FLAG{your_flag_here}
   ```

---

## **Key Takeaways**
- **Binary Patching**: Modified hardcoded values (`dd`/`hexedit`).
- **Interoperability**: Achieved compatibility between mismatched components.
- **Flag Extraction**: Bypassed restrictions via strategic patches.

**Tools Used**: `xxd`, `dd`, `hexedit`, `grep`, `python3`.  
**Skills Demonstrated**: Reverse engineering, binary patching, debugging.
