## Challenge: Level 25 – *internal state (x86)*

In this reverse engineering challenge, we’re given a stripped x86 ELF binary called `cimg` that expects a `.cimg` image file. There is no source code provided, and the goal is to figure out the correct format of this `.cimg` file and craft a valid one to get the flag when running:

```bash
./cimg < solution.cimg
```

---

## Goal

Craft a valid `.cimg` file that, when passed as input to the binary, triggers the internal rendering logic and eventually reveals the **flag**.

---

## Step-by-Step Solution

### Step 1: Understand the Binary Output

The binary uses terminal graphics (ANSI escape sequences) to render an image. Using:

```bash
strings ./cimg | less
```

We could locate hints like:

```
[38;2;255;255;255m.[0m
```

This is an ANSI escape sequence indicating:

* `\x1b[38;2;R;G;Bm<CHAR>\x1b[0m` – which sets the foreground color in RGB and prints a character.

This indicates the output is composed of RGB-colored characters — likely rendered from internal image data (`desired_output` buffer in the binary).

---

### Step 2: Locate Internal Data Using IDA

We used **IDA Freeware** to reverse the binary and look at the `.rodata` or `.data` section. There, we found the internal `desired_output` buffer starting at:

```
0x404020 to 0x40b8e0
```

This buffer is responsible for the full terminal-rendered image. It's likely what the output of a correct `.cimg` file should match.

---

### Step 3: Dump `desired_output` to a File

We dumped the contents of this region using GDB:

```bash
gdb ./cimg
(gdb) dump memory desired_output.txt 0x404020 0x40b8e0
```

This gave us a file (`desired_output.txt`) with raw ANSI-rendered text, like:

```
[38;2;255;255;255m.[0m[38;2;255;255;255m-[0m...
```

---

### Step 4: Parse the Rendered Output

We then wrote a Python script to extract RGB values and the characters from the ANSI sequences using a regular expression.

```python
pattern = re.compile(r'\x1b\[38;2;(\d+);(\d+);(\d+)m(.)\x1b\[0m')
```

This matches:

* Red (`r`), Green (`g`), Blue (`b`) values
* A single character (`char`)

We looped over all matches and stored them:

```python
pixels.append((r, g, b, char))
```

We also printed the **number of pixels** found:

```python
print(f"Total pixels found: {len(pixels)}")  # This helped us brute-force width x height
```

---

### Step 5: Fuzz Width & Height

Knowing the total pixel count (e.g., 1288), we brute-forced possible `width x height` values until the image looked correct. Eventually, we discovered:

```python
width = 56
height = 23
```

---

### Step 6: Craft the `.cimg` File

From earlier challenges or binary reverse engineering, we inferred the `.cimg` file format:

| Field      | Type    | Description              |
| ---------- | ------- | ------------------------ |
| Magic      | 4 bytes | "cIMG"                   |
| Version    | 2 bytes | LE uint16 (e.g., `2`)    |
| Width      | 1 byte  | Width of image           |
| Height     | 1 byte  | Height of image          |
| Pixel Data | N bytes | Array of (R, G, B, CHAR) |

Each pixel is stored as **4 bytes**: RGB + ASCII char (so 1288 pixels × 4 = 5152 bytes).

Crafting was done with:

```python
header = (
	b"cIMG" +
	struct.pack("<H",2) +
	struct.pack("<B", width) +
	struct.pack("<B", height)
)
```

Then writing the data:

```python
for r, g, b, char in pixels:
	data += struct.pack("BBBB", r, g, b, ord(char))
```

Finally, we padded any remaining pixels:

```python
remaining = width * height - len(pixels)
for _ in range(remaining):
	data += struct.pack('BBBB', 0, 0, 0, 32)  # Pad with black space
```

---

### Step 7: Run the Binary

```bash
./cimg < solution_25.cimg
```

 **The image rendered correctly**, and the **flag appeared in the terminal**.

---

## Final Script Summary

```python
#!/bin/python3
import re, struct

with open("desired_output.txt", "r", encoding="utf-8") as f:
	data = f.read()

pattern = re.compile(r'\x1b\[38;2;(\d+);(\d+);(\d+)m(.)\x1b\[0m')
pixels = [(int(r), int(g), int(b), char) for r, g, b, char in pattern.findall(data)]

width = 56
height = 23

header = b"cIMG" + struct.pack("<H", 2) + struct.pack("<B", width) + struct.pack("<B", height)
data = b''.join([struct.pack("BBBB", r, g, b, ord(char)) for r, g, b, char in pixels])

with open("solution_25.cimg", "wb") as f:
	f.write(header)
	f.write(data)
	f.write(b'\x00\x00\x00\x20' * (width * height - len(pixels)))  # padding
```

---

## Lessons Learned

* ANSI escape sequences can be reverse engineered with regex and pattern matching.
* Even in stripped binaries, **memory inspection** (GDB) and **IDA disassembly** allow reverse-engineering hidden buffers.
* Pixel data stored in structs can be reconstructed from terminal outputs.
* **Fuzzing dimensions** (width × height) is a useful brute-force technique for image data layout recovery.

---

## Flag

The flag was revealed upon running the correct `.cimg` file.

