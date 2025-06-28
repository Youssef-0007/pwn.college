#!/usr/bin/env python3

import re
import struct
from collections import namedtuple, defaultdict

# Settings
WIDTH = 76
HEIGHT = 24
DIRECTIVE_52965 = struct.pack("<H", 52965)

# Parse ANSI color-formatted text from desired_output
with open("desired_output.txt", "r", encoding="utf-8") as f:
    data = f.read()
    print(f"desired_output size: {len(data)}")

pattern = re.compile(r'\x1b\[38;2;(\d+);(\d+);(\d+)m(.)\x1b\[0m')
Pixel = namedtuple("Pixel", "x y r g b char")

pixels = []
x = y = 0
for match in pattern.finditer(data):
    r, g, b = int(match.group(1)), int(match.group(2)), int(match.group(3))
    char = match.group(4)
    pixels.append(Pixel(x, y, r, g, b, char))
    x += 1
    if x >= WIDTH:
        x = 0
        y += 1

print(f"Total pixels found: {len(pixels)}")

# Filter usable pixels (inside bounds and non-space)
filtered = [p for p in pixels if p.char != ' ' and  (0 < p.x < 75) and (0 < p.y < 23)]
rows = defaultdict(dict)
for p in filtered:
    rows[p.y][p.x] = p

# Create patches row by row, allowing 1 space in between
patches = []
for y in sorted(rows):
    row = rows[y]
    sorted_x = sorted(row.keys())
    i = 0
    while i < len(sorted_x):
        start_x = sorted_x[i]
        patch_pixels = [row[start_x]]
        current_x = start_x
        i += 1
        while i < len(sorted_x):
            next_x = sorted_x[i]
            gap = next_x - current_x
            if gap == 1:
                patch_pixels.append(row[next_x])
                current_x = next_x
                i += 1
            elif gap == 2:
                # Fill 1 gap with explicit space pixel
                space_pixel = Pixel(current_x + 1, y, 255, 255, 255, ' ')
                patch_pixels.append(space_pixel)
                patch_pixels.append(row[next_x])
                current_x = next_x
                i += 1
            else:
                break

        # Create patch
        patch_header = (
            struct.pack("B", patch_pixels[0].x) +
            struct.pack("B", patch_pixels[0].y) +
            struct.pack("B", len(patch_pixels)) +
            struct.pack("B", 1)
        )
        patch_data = b''.join(struct.pack("BBBB", p.r, p.g, p.b, ord(p.char)) for p in patch_pixels)
        patches.append((DIRECTIVE_52965, patch_header + patch_data))

# Create border patches
def make_border_patch(x, y, w, h, ch):
    patch = struct.pack("BBBB", x, y, w, h)
    patch += struct.pack("BBBB", 255, 255, 255, ord(ch)) * (w * h)
    return patch

TopBorder    = make_border_patch(0, 0, 76, 1, '-')
TopBorder    = TopBorder[:4] + struct.pack("BBBB", 255, 255, 255, ord('.')) + TopBorder[8:-4] + struct.pack("BBBB", 255, 255, 255, ord('.'))
BottomBorder = make_border_patch(0, 23, 76, 1, '-')
BottomBorder = BottomBorder[:4] + struct.pack("BBBB", 255, 255, 255, ord('\'')) + BottomBorder[8:-4] + struct.pack("BBBB", 255, 255, 255, ord('\''))
LeftBorder   = make_border_patch(0, 1, 1, 22, '|')
RightBorder  = make_border_patch(75, 1, 1, 22, '|')

# Build header
header = (
    b"cIMG" +
    struct.pack("<H", 3) +
    struct.pack("B", WIDTH) +
    struct.pack("B", HEIGHT) +
    struct.pack("<I", len(patches) + 4)
)

# Track total_data like in C code
total_data = 0

# Write to output
with open("solution_with_1space_patch.cimg", "wb") as f:
    f.write(header)

    for name, border in [("Top", TopBorder), ("Left", LeftBorder), ("Right", RightBorder), ("Bottom", BottomBorder)]:
        f.write(DIRECTIVE_52965)
        f.write(border)
        border_size = 2 + len(border)
        total_data += border_size
        print(f"[+] {name} Border: {len(border)} bytes (running total: {total_data}\n)")

    for idx, (directive, patch) in enumerate(patches):
        f.write(directive)
        f.write(patch)
        total_data += 2 + len(patch)
        print(f"patch {idx}: {patch}... len={len(patch)} (total={total_data}\n)")

print(f"\n✅ Total data sent (excluding header): {total_data} bytes")
print("⚠️ Must be ≤ 1337 for flag to print.")

