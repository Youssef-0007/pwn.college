#!/bin/python3

import re
import struct
from collections import namedtuple, defaultdict

width = 55
height = 15

directive_17571 = struct.pack("<H", 17571)
directive_47594 = struct.pack("<H", 47594)

with open("desired_output.txt", "r", encoding="utf-8") as f:
	data = f.read()
	print(f"desired_output size: {len(data)}")

pattern = re.compile(r'\x1b\[38;2;(\d+);(\d+);(\d+)m(.)\x1b\[0m')

Pixel = namedtuple("Pixel", "x y r g b char")

pixels_with_pos = []

x = 0
y = 0

pixels = []
for match in pattern.finditer(data):
	r = int(match.group(1))
	g = int(match.group(2))
	b = int(match.group(3))
	char = match.group(4)
	pixels.append((r,g,b,char))
	
	pixels_with_pos.append(Pixel(x, y, r, g, b, char))
	
	x += 1
	if x >= width:
		x = 0
		y += 1

print(f"Total pixels found: {len(pixels)}")


interesting_chars = {'-', '|', '\\', '/', '.', '_', '\'', '(', ')'}

filtered_pixels = [ p for p in pixels_with_pos if (p.char not in ' ' and (p.x > 0 and p.x < 54) and (p.y > 0 and p.y < 14)) ]
remaining_directives = len(filtered_pixels)
print(f"filtered pixels: {remaining_directives}")

rows = defaultdict(list)

for p in filtered_pixels:
    rows[p.y].append(p)

all_patch_directives = []
# sort by row
for y in sorted(rows):
    row_pixels = sorted(rows[y], key=lambda p: p.x)

    # create a patch for continuous run in each row
    i = 0
    while i < len(row_pixels):
        start = row_pixels[i]
        run = [start]
        i += 1
        while i < len(row_pixels) and row_pixels[i].x == run[-1].x + 1:
            run.append(row_pixels[i])
            i += 1
        
        patch_width = len(run)
        patch_height = 1
        patch_data = (
            struct.pack("<B", run[0].x) +
            struct.pack("<B", run[0].y) +
            struct.pack("<B", patch_width) +
            struct.pack("<B", patch_height)
        )

        for px in run:
            patch_data += struct.pack("BBBB", px.r, px.g, px.b, ord(px.char))
        
        all_patch_directives.append((directive_47594, patch_data))

header = (
	b"cIMG" +
	struct.pack("<H",3) +
	struct.pack("<B", width) +
	struct.pack("<B", height) +
	struct.pack("<I", len(all_patch_directives) + 4)
)

print(f"number of patches directives {len(all_patch_directives) + 4}")

TopBoarder = struct.pack("<B", 0) + struct.pack("<B", 0) + struct.pack("<B", 55) + struct.pack("<B", 1) + struct.pack("BBBB", 255,255,255,ord('.')) + (struct.pack("BBBB", 255,255,255,ord('-')) * 53) + struct.pack("BBBB", 255,255,255,ord('.'))

ButtomBoarder = struct.pack("<B", 0) + struct.pack("<B", 14) + struct.pack("<B", 55) + struct.pack("<B", 1) + struct.pack("BBBB", 255,255,255,ord('\'')) + (struct.pack("BBBB", 255,255,255,ord('-')) * 53) + struct.pack("BBBB", 255,255,255,ord('\''))

LeftBoarder = struct.pack("<B", 0) + struct.pack("<B", 1) + struct.pack("<B", 1) + struct.pack("<B", 13) +  (struct.pack("BBBB", 255,255,255,ord('|')) * 13)

RightBoarder = struct.pack("<B", 54) + struct.pack("<B", 1) + struct.pack("<B", 1) + struct.pack("<B", 13) +  (struct.pack("BBBB", 255,255,255,ord('|')) * 13)
	

with open("solution_28.cimg", "wb") as f:
	f.write(header)
	
	f.write(directive_47594)
	f.write(TopBoarder)
	
	f.write(directive_47594)
	f.write(LeftBoarder)
	
	f.write(directive_47594)
	f.write(RightBoarder)
	
	f.write(directive_47594)
	f.write(ButtomBoarder)
	
	"""
	for p in filtered_pixels:
		f.write(directive_47594)
		letter = struct.pack("<B", p.x) + struct.pack("<B", p.y) + struct.pack("<B", 1) + struct.pack("<B", 1) +  struct.pack("BBBB", p.r, p.g, p.b, ord(p.char))
		f.write(letter)
	"""
	for d, data in all_patch_directives:
		f.write(d)
		f.write(data)
