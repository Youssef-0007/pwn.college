# CIMG Reverse Engineering Challenge level 24 Write-Up

## Challenge Summary

The challenge provides a binary called `cimg` that takes a `.cimg` image file and prints a terminal-rendered colored image. However, no valid `.cimg` file is provided. Our objective was to reconstruct or reverse-engineer a valid `.cimg` file based on the behavior of the program to ultimately extract or render a flag.

---

## Step-by-Step Write-Up

---

### Step 1: Understanding the Program Behavior

We began by observing the behavior of the `cimg` binary:

* It reads a `.cimg` file.
* It prints colored characters using ANSI escape sequences (`\x1b[38;2;r;g;bm<char>\x1b[0m`).
* This format suggests it's displaying characters with RGB colors.

This led to a hypothesis:

> The image format must contain RGB values and ASCII characters for each pixel.

---

### Step 2: Using GDB to Reverse Engineer Structure

We loaded the binary in `gdb`:

```bash
gdb ./cimg
```

We set a breakpoint at the `display()` function:

```gdb
(gdb) break display
```

After running the program with a sample or dummy `.cimg` file, we inspected variables:

```gdb
(gdb) print cimg->header.width
(gdb) print cimg->header.height
```

This confirmed the presence of a `header` with a `width` and `height`, likely part of a C struct like:

```c
typedef struct {
    char magic[4];     // 'cIMG'
    uint16_t version;  // e.g. 2
    uint8_t width;
    uint8_t height;
} cimg_header_t;
```

So, the file structure is likely:

```
| 4 bytes  | 2 bytes  | 1 byte  | 1 byte  |
| "cIMG"   | version  | width   | height  |
```

Followed by:

```
width × height × sizeof(pixel)
```

Where each `pixel` consists of:

```c
typedef struct {
    uint8_t r, g, b, ch;
} term_pixel_t;
```

---

### Step 3: Testing Fuzzed Header and Pixel Data

We used a manually constructed `.cimg` file with dummy data to test format validity. We realized:

* The binary **does not validate width × height** with file size, allowing us to guess width/height combinations.
* If the pixel data is shorter than expected, it may read garbage or crash.

We calculated that:

```python
num_pixels = len(output) // len('\x1b[38;2;r;g;bmX\x1b[0m')
```

After visual inspection of the output, we estimated the number of pixels as **962**, then fuzzed width and height combinations like:

```python
width = 26
height = 37  # 26 x 37 = 962
```

---

### Step 4: Extracting Pixels from Terminal Output

We parsed the program's output (copied from the terminal) using Python:

```python
output = """<copied ANSI output from cimg>"""
```

We split by the ANSI reset sequence to get individual pixels:

```python
pixel_strings = output.split('\x1b[0m')[:-1]
```

We extracted the RGB and character values:

```python
for ps in pixel_strings:
    ansi_part, char_part = ps.split('m', 1)
    parts = ansi_part.split(';')
    r = int(parts[2])
    g = int(parts[3])
    b = int(parts[4])
    char = char_part[0]
    pixels.append((r, g, b, char))
```

---

### Step 5: Building a Valid `.cimg` File

We reconstructed a binary `.cimg` file using Python:

```python
import struct

header = (
    b"cIMG" +
    struct.pack("<H", 2) +           # Version = 2
    struct.pack("<B", width) +       # Width
    struct.pack("<B", height)        # Height
)

data = b""
for r, g, b, char in pixels:
    data += struct.pack("BBBB", r, g, b, ord(char))  # ord() to get ASCII int

# Pad remaining pixels if needed
remaining = width * height - len(pixels)
for _ in range(remaining):
    data += struct.pack("BBBB", 0, 0, 0, 32)  # Space pixel

with open("solution.cimg", "wb") as f:
    f.write(header)
    f.write(data)
```

---

### Step 6: Final Execution

We ran the final command:

```bash
./cimg < solution.cimg
```

And **the flag was revealed** as part of the rendered terminal image 🎉

---

## Key Takeaways

* **GDB helped understand internal structures** (headers, pixels).
* **Terminal escape sequences were the key** to decoding the output.
* **No strict input validation** allowed fuzzing to work.
* **Combining reverse engineering with scripting** allowed rapid iteration and automation.

---

## Flag

*The flag was revealed in the rendered output of the reconstructed `solution.cimg' file.
