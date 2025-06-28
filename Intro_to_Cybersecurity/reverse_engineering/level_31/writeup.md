## 🧩 Challenge: Storage and Retrieval

### 🔒 Description

In this level, you're tasked with rendering an image that resembles a flag using the `cIMG` file format. The twist: you **must use less than 400 bytes of directives** to reproduce the desired output. This challenge requires:

* Efficient **compression of pixel data**
* Exploiting sprite reuse via directives `handle_3` (define sprite) and `handle_4` (render sprite)
* A deep understanding of how to **reuse repeated patterns** in terminal-rendered graphics

---

## 🧠 Core Concepts

### 🖼️ cIMG Format Recap

* **Header**: Contains metadata (magic, version, width, height, number of directives)
* **Directives**:

  * `handle_3`: Defines a sprite (`sprite_id`, `width`, `height`, and raw character data)
  * `handle_4`: Places that sprite (`sprite_id`, `r, g, b`, `x`, `y`)
* **24-bit color** is used for each character using ANSI escape sequences
* Every directive contributes to the byte count, so **minimizing data** is crucial

---

## 🔍 Reverse Engineering Observations

* The `desired_output.txt` contained many **repeated visual patterns**:

  * Long horizontal lines (`-----`)
  * Vertical borders (`|`, `.`)
  * Blocks of space and characters with the same RGB
* The game engine allowed for **sprite reuse**, which became the core optimization goal

---

## ⚙️ Final Strategy & Script Explanation

### 📁 File Parsing & Pixel Extraction

You read the file using regex to parse:

```plaintext
\x1b[38;2;R;G;BmCHAR\x1b[0m
```

Converted each position into a `Pixel` namedtuple with `(x, y, r, g, b, char)`.

### 🧱 Sprite Strategy: Region-Based Grouping

1. **Border Detection**

   * Identified top, bottom, left, and right borders based on their positions
   * Reused large consistent lines like `-----` and `|` to make **1×N** or **N×1** reusable sprites

2. **Color-Based Grouping**

   * Grouped remaining pixels by `(r, g, b)`
   * For each group, you analyzed its **bounding rectangle** and **density**
   * Created one large composite sprite if:

     * Area was small, or
     * Density (non-space pixels / area) was high

3. **Character-Based Grouping**

   * Within color groups, you further grouped pixels by character
   * Horizontal lines (e.g., `'---'`, `'==='`) were extracted as 1D line sprites

4. **Fallback: Single-Pixel Sprites**

   * For pixels that couldn't be grouped efficiently, you fell back to defining them as individual 1×1 sprites

---

## 📦 Final Output: Optimized Directives

You generated:

* **Sprite Definitions** using `handle_3`
* **Sprite Placements** using `handle_4`

And built the final `.cimg` file with:

```python
write_cimg_file(OUTPUT_CIMG_PATH, directives_count)
```

---

## 📊 Results Summary

* ✅ Flag rendered correctly
* ✅ File compiled successfully with valid header and directives
* ❗ Your script included detailed **debugging printouts** of:

  * Pixel color stats
  * Sprite sizes and content
  * Byte usage breakdowns

```plaintext
Sprite count: X
Placement count: Y
Total bytes sent: Z
Within limit: ✅ YES
```

---

## 🛠️ Tools & Skills Used

### Tools:

* Python (regex, struct, collections)
* Terminal ANSI escape decoding
* Manual GDB memory inspection (for earlier image extraction)

### Skills:

* Reverse engineering
* Terminal rendering logic
* Compression techniques
* Data structure design
* Greedy optimization and density scoring

---

## 💡 Lessons Learned

* **Pattern reuse** is the key to compact rendering.
* A mix of **static heuristics** (like borders) and **dynamic optimization** (like bounding boxes) leads to the best results.
* Designing an efficient **sprite table** can significantly compress rendering data.

---

## 🏁 Final Thoughts

This challenge simulated real-world constraints like:

* Limited bandwidth
* Space-efficient UI rendering
* Sprite-based drawing logic

