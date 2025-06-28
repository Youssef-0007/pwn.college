# 📄 Writeup – Pwn.college Reverse Engineering Challenge: `level_30` – *Directives and cIMG Format*

## 🧠 Challenge Overview

In this challenge, we are provided with a custom binary image file format called `cIMG`. Our task is to **analyze**, **understand**, and **patch** the file so that a hidden flag (rendered as ASCII art) can be displayed properly using the `/challenge/cimg` viewer tool.

The main difficulty is that:

* The `flag.cimg` file is obfuscated using an unfamiliar or corrupted directive code.
* The file loads, but does not display anything meaningful when opened with the official renderer.
* There is no documentation provided for the format — we must reverse engineer it.

---

## 🎯 Goal

* Understand the structure of `.cimg` files.
* Reverse engineer the directive codes to uncover the intended image.
* Patch the flag file so it renders the hidden ASCII flag.
* Extract the rendered ASCII flag and recover the actual `pwn.college{...}` string.

---

## 🧰 Tools Used

* Python (for scripting and patching)
* Hex editors (e.g., `hexdump`, `xxd`, or Python’s `bytearray`)
* `figlet` / `pyfiglet` (for recognizing ASCII art patterns)
* Terminal-based manual testing (`/challenge/cimg patched_flag.cimg`)
* Debugging via print statements

---

## 🛠️ Skills Practiced / Gained

* Reverse engineering a custom binary file format
* Working with binary data using Python
* Byte-level patching
* Understanding and manipulating rendering directives
* ASCII art pattern matching and character recognition
* File format parsing and header manipulation
* Debugging visual output via command line tools

---

## 🧩 Analysis and Thought Process

### 🔍 Step 1: Analyze the File Header

Initial analysis showed that the `.cimg` file starts with a fixed structure:

```
Offset 0x00: Magic bytes         -> cIMG
Offset 0x04: Version?            -> 0x03 0x00
Offset 0x06: Width               -> 0x4D (77)
Offset 0x07: Height              -> 0x01 (suspicious)
Offset 0x08: Directive count     -> 0x0EBD = 3773
```

Observation:

* The **width** is `77` pixels.
* The **height** is `1`, which is too small for 3773 directives. This hints that **height must be incorrect**.

> 💡 Calculated height = 3773 / 77 = 49 (rounded), which makes sense for a full ASCII art rendering.

---

### 🧪 Step 2: Initial Attempts to Parse or Render

Using `/challenge/cimg flag.cimg` displayed only garbage or nothing useful. A Python parser also failed to make sense of the pixel layout, as directive code `0x0002` didn't have enough metadata (e.g., X, Y positions), indicating it's likely **a compressed or relative directive**.

---

### 🔨 Step 3: Patch the Header and Directives

We wrote a Python script to:

* Modify the height byte in the header from `1` → `49`
* Replace directive opcode `0x0002` (compressed format) with `0xE8C2` (59586 in decimal), which we knew was **a full coordinate directive** based on prior challenges

```python
with open("/challenge/flag.cimg", "rb") as f:
    data = bytearray(f.read())

data[7] = 49  # Patch height in header

i = 12  # Start after header
while i < len(data):
    if data[i] == 0x02 and data[i+1] == 0x00:
        data[i] = 0xC2  # 0xE8C2 = 59586
        data[i+1] = 0xE8
    i += 10  # Each directive is 10 bytes

with open("patched_flag.cimg", "wb") as f:
    f.write(data)
```

> 📌 This ensures all directives now contain full information (x, y, color, character), allowing proper rendering.

---

### 🖼️ Step 4: View the Patched Image

Running:

```bash
/challenge/cimg patched_flag.cimg
```

…finally displayed a huge **ASCII art banner** that visually resembled `pwn.college{...}` but was hard to read.

---

### 🔡 Step 5: Extract the Flag from ASCII Art

To extract the flag from ASCII-art:

* Used `pyfiglet` to generate every character (0-9, a-z, A-Z, `{}`, etc.) in the same font (`small`)
* Matched each section of the ASCII image to known characters using pattern comparison
* Reconstructed the flag

Snippet:

```python
from pyfiglet import Figlet

ascii_art_lines = [...]  # captured from /challenge/cimg output
fig = Figlet(font='small')

rendered_chars = {c: fig.renderText(c).split('\n') for c in "pwn.college{}0123456789"}

# Logic to match character blocks...
```

---

## ✅ Final Outcome

We successfully extracted the hidden flag from the corrupted `.cimg` file by:

* Patching the directive codes
* Fixing the height in the header
* Matching rendered ASCII art to characters

> **Flag:** `pwn.college{<REDACTED-FLAG-HERE>}`

---

## 📘 Lessons Learned

* Binary file formats often include a magic header and structured layout; reverse engineering starts there.
* Small values (like width/height) can drastically affect how files are rendered or interpreted.
* It’s critical to understand **how directive codes work**, especially if there are compressed vs uncompressed formats.
* ASCII art recognition using tools like `figlet` or `pyfiglet` is a valuable skill in visual CTF challenges.

