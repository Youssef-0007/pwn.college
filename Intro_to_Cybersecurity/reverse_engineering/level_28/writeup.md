#  CTF Challenge Write-Up: `file formats: directives (C)` – cIMG Format Reverse Engineering

---

## Challenge Overview

This challenge presented a custom image file format `.cimg` with obscure binary rendering logic. We were provided with a compiled binary that interprets `.cimg` files and prints colored ASCII art to the terminal. The objective was to **reverse engineer the format** and **create a valid `.cimg`** file that reproduces a given image (stored in `desired_output.txt`) to get the **flag**.

---

## Tools Used

| Tool                          | Purpose                                                                           |
| ----------------------------- | --------------------------------------------------------------------------------- |
| **Ghidra**                    | Reverse engineering the compiled binary; understanding `handle_xxxxx()` functions |
| **GDB**                       | Live memory inspection and dumping the raw output (`desired_output.raw`)          |
| **Python**                    | Parsing, filtering, and reconstructing `.cimg` binary                             |
| **Hex editors (xxd/hexdump)** | Manual inspection of raw memory or file data                                      |
| **Regex**                     | Extracting ANSI-colored pixels from the desired image                             |

---

## Phase 1: Extracting the Desired Output Image

### Step 1: Running the Program and Observing Behavior

We noticed the binary reads a `.cimg` file and displays a colored ASCII image. However, we had only the **final printed image in `desired_output.txt`** and no matching `.cimg` input.

To generate a matching `.cimg`, we had to reverse-engineer:

* The **binary's internal logic**
* The **structure of `.cimg`**
* The **rendering flow and directives**

---

## Phase 2: Reverse Engineering with Ghidra

### Step 2: Analyze `main()` and Dispatcher

* The binary had a typical `main()` → `parse_header()` → `read_directives()` structure.
* Each directive was processed by a `handle_XXXXX()` function (e.g., `handle_47594`, `handle_17571`).
* Using Ghidra, we renamed and decompiled these handlers to understand:

#### `handle_47594`:

* Reads: `x`, `y`, `w`, `h`
* Then reads `w * h * 4` bytes: each pixel is `r, g, b, char`
* Draws a colored rectangle starting at `(x,y)`

#### `handle_17571`:

* A compressed directive
* Parameters: `x`, `y`, `count`, and 4 bytes (r, g, b, char)
* Repeats the same pixel `count` times horizontally from `(x,y)`

---

## Phase 3: Dumping the In-Memory Rendered Output with GDB

### Step 3: Identify Render Buffer

Using Ghidra and some debugging in GDB:

* We located the **render buffer address range**: `0x404020` to `0x408d79`

### Step 4: Dump the Rendered Output

```bash
gdb ./render_binary
(gdb) run < input.cimg
# After the image is printed
(gdb) dump memory desired_output.raw 0x404020 0x408d79
```

We now had `desired_output.raw`, a raw memory dump of the in-memory rendered output.

---

## Step 5: Convert Raw Dump to Human-Readable UTF-8

```bash
xxd desired_output.raw > desired_output.hex
cat desired_output.raw | iconv -f utf-8 -t utf-8 -c > desired_output.txt
```

* We used `iconv` to filter out non-printable/invalid bytes
* This gave us **clean, colored ASCII art** (with ANSI escape codes) in `desired_output.txt`

---

## Phase 4: Parsing the Colored Image

### Step 6: Extract Colored Pixels with Regex

Each colored character is stored as:

```
\x1b[38;2;R;G;Bm<char>\x1b[0m
```

We used this regex to extract the pixel data:

```python
pattern = re.compile(r'\x1b\[38;2;(\d+);(\d+);(\d+)m(.)\x1b\[0m')
```

And reconstructed the image as:

```python
Pixel = namedtuple("Pixel", "x y r g b char")
```

Tracked X and Y positions across a 55×15 grid.

---

## Phase 5: Cleaning & Structuring the Pixels

* Removed **spaces** and **border characters** from the main image
* Border would be encoded manually
* Only internal interesting pixels were added to `filtered_pixels`

```python
filtered_pixels = [
    p for p in pixels_with_pos
    if (p.char != ' ' and 0 < p.x < 54 and 0 < p.y < 14)
]
```

---

## Phase 6: Grouping Pixels into Efficient Patches

Sending each pixel as a separate directive (`47594`) was inefficient.

Instead, we **grouped consecutive pixels horizontally** and sent them as one patch:

```python
# Grouped by row → sorted by x → grouped consecutive x
```

Generated a single patch:

```c
x_start, y, width=run_length, height=1
```

Followed by:

```c
patch_data = [r, g, b, char] * run_length
```

This optimization reduced hundreds of directives into just \~100 patch groups.

---

## Phase 7: Manual Borders Using `handle_47594`

Constructed the top, bottom, left, and right borders using a single `47594` directive each:

```python
TopBorder = ...
LeftBorder = ...
RightBorder = ...
BottomBorder = ...
```

We kept these fixed since their positions and characters were known.

---

## Phase 8: File Header Structure

```python
header = (
    b"cIMG" +
    struct.pack("<H", 3) +
    struct.pack("<B", width) +
    struct.pack("<B", height) +
    struct.pack("<I", total_directive_count)
)
```

* Magic bytes: `cIMG`
* Version: 3
* Width: 55
* Height: 15
* Number of directives: `len(patches) + 4 (for borders)`

---

## 📦 Phase 9: Final File Construction

```python
with open("solution.cimg", "wb") as f:
    f.write(header)
    f.write(borders)           # 4 border directives
    f.write(all_patch_directives)  # patch data
```

Successfully generated `.cimg` with accurate header, efficient patching, and valid structure.

---

## Result

When we ran the binary with our crafted `.cimg`:

```
$ ./render_binary < solution_28.cimg
[...image...]
🎉 FLAG{...}
```

---

## 🧠 Key Takeaways

| Concept                       | Explanation                                                       |
| ----------------------------- | ----------------------------------------------------------------- |
| 🔍 **Ghidra**                 | Reverse engineered directive handlers to understand binary format |
| 🧵 **GDB**                    | Dumped raw render buffer to retrieve final image                  |
| 📜 **Regex**                  | Extracted structured color+char data from ANSI escape sequences   |
| 🧱 **Binary encoding**        | Crafted `.cimg` files with correct headers and directives         |
| ⚙️ **Optimization**           | Combined horizontal pixels into patches for efficiency            |
| 🎨 **Custom rendering logic** | Respected render layout, colors, and characters                   |

---

## 📁 File Tree for GitHub

```
cimg-challenge/
├── desired_output.txt         # Cleaned UTF-8 colored image
├── desired_output.raw         # Memory dump
├── parse_and_build.py         # Full working solution script
├── solution_28.cimg           # Final crafted image
├── ghidra_analysis.md         # Ghidra handler analysis notes
├── writeup.md                 # (This) Complete writeup
```

