## 🧠 Challenge: `optimizing-for-space`

### 📝 Description

> This **side-quest** in the *Reverse Engineering* module builds on the previous `directives` challenge. The goal is the same: reconstruct an image using the cIMG binary format—but this time, you're restricted in how many bytes you're allowed to send.
>
> **Goal:** Render an image that matches the `desired_output`, but **do not exceed `1337` bytes of data** in total.

---

## 🎯 Objective

Display a precise image (stored in a hidden `desired_output` buffer inside the binary), using two supported **rendering directives**:

* `handle_55369()` — legacy full-frame image mode (non-optimal for partial rendering)
* `handle_52965()` — flexible patch-based rendering using `x, y, width, height + pixel data`

...while keeping the **entire input payload ≤ 1337 bytes** — including:

* Directives (2 bytes each)
* Patch metadata (4 bytes each)
* Pixel data (4 bytes per pixel)

When the framebuffer matches the hidden `desired_output` and total\_data ≤ 1337, the binary calls `win()`, printing the flag.

---

## 🔍 Reverse Engineering Breakdown

### 1. **Analyzing the ELF**

* We reverse engineered the stripped binary with **Ghidra** to locate and decompile the two main rendering functions:

#### 🧩 `handle_55369()`

* Loads a full image as a flat RGB/ASCII array (width × height × 4 bytes)
* Writes it to the framebuffer using modulo-based positioning
* ❌ **Inefficient** for large or sparse images (forces full image + many spaces)

#### ✅ `handle_52965()`

* Reads: `base_x`, `base_y`, `width`, `height`, and a series of pixels (4 bytes each)
* Efficient for small image patches
* **Perfect for this optimization challenge**

---

## 🧪 Dynamic Analysis

### 🧠 Strategy to Understand `desired_output`

1. **Used GDB** to dump memory from the symbol:

   ```bash
   dump memory desired_output.raw 0x404020 0x408d79
   ```

2. **Converted binary dump** to UTF-8 using:

   ```python
   open("desired_output.raw", "rb").read().decode("utf-8")
   ```

3. Saved the result to `desired_output.txt` and parsed using a regex:

   ```python
   r'\x1b\[38;2;(\d+);(\d+);(\d+)m(.)\x1b\[0m'
   ```

   This matches **ANSI escape sequences** used in the terminal to draw the image.

---

## 🧠 Optimization Design

### ✔️ What We Discovered

* The image includes:

  * White **borders** (`.`, `-`, `|`, `'`)
  * Centered text/art made of `-`, `/`, `|`, etc.
  * Very **sparse** pixels: long rows/columns of mostly **spaces**

### 💡 Core Optimization Ideas

* Using **patch-based rendering (`handle_52965`)**
* **Group pixels by row**, sending continuous runs
* **Allow 1 space between characters** to avoid splitting into two patches:

  * Sending a `' '` costs 4 bytes
  * Starting a new patch costs 6 bytes (2 for directive, 4 for x/y/w/h)
  * So sending 1 space is better than starting a new patch: **saves 2 bytes**

---

## 🧰 Final Implementation

### Script Highlights:

```python
# Filtering only visible characters inside bounds
filtered = [p for p in pixels if p.char != ' ' and (0 < p.x < 75) and (0 < p.y < 23)]

# Grouping by row
rows = defaultdict(dict)
for p in filtered:
    rows[p.y][p.x] = p

# Merging runs with at most 1-space gaps
if gap == 1:
    patch_pixels.append(next_pixel)
elif gap == 2:
    patch_pixels.append(Pixel(x+1, y, 255,255,255,' '))
    patch_pixels.append(next_pixel)
else:
    break
```

### Border Rendering:

All four borders are rendered using single patches to minimize overhead.

```python
TopBorder = make_border_patch(0, 0, 76, 1, '-')
BottomBorder = make_border_patch(0, 23, 76, 1, '-')
LeftBorder = make_border_patch(0, 1, 1, 22, '|')
RightBorder = make_border_patch(75, 1, 1, 22, '|')
```

### Final Output:

```bash
✅ Total data sent (excluding header): 1322 bytes
⚠️ Must be ≤ 1337 for flag to print.
🎉 Flag displayed successfully!
```

---

## 📦 Output File

The script outputs a `.cimg` file which, when run using:

```bash
./cimg solution_with_1space_patch.cimg
```

...produces the correct image **and displays the flag**, confirming success.

---

## 🔚 Conclusion

This challenge was a hands-on exercise in:

* Binary format reverse engineering
* Low-level image processing
* Tradeoff-based byte-level optimization
* Understanding how to exploit the **cost model** of custom rendering engines

💪 We combined reverse engineering, scripting, and optimization to hit the target **with only 1322 bytes used — under the 1337 limit**.

---

## 🧰 Tools Used

| Tool     | Purpose                           |
| -------- | --------------------------------- |
| `Ghidra` | Static analysis and decompilation |
| `gdb`    | Runtime memory inspection         |
| `Python` | Image construction & encoding     |
| `Regex`  | ANSI escape parsing               |
| `struct` | cIMG binary patch formatting      |

