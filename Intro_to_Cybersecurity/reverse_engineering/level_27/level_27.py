#!/bin/python3

import re
import struct


with open("desired_output.txt", "r", encoding="utf-8") as f:
	data = f.read()
	print("desired_output file opened successfully!")

pattern = re.compile(r'\x1b\[38;2;(\d+);(\d+);(\d+)m(.)\x1b\[0m')

pixels = []
for match in pattern.finditer(data):
	r = int(match.group(1))
	g = int(match.group(2))
	b = int(match.group(3))
	char = match.group(4)
	pixels.append((r,g,b,char))

print(f"Total pixels found: {len(pixels)}")

width = 53
height = 21
remaining_directives = 1

header = (
	b"cIMG" +
	struct.pack("<H",3) +
	struct.pack("<B", width) +
	struct.pack("<B", height) +
	struct.pack("<I", remaining_directives)
)

directive_code = struct.pack("<H", 4759)


data = b""
for r, b, g, char in pixels:
	data += struct.pack("BBBB", r, b, g, ord(char))

		
with open("solution_27.cimg", "wb") as f:
	f.write(header)
	f.write(directive_code)
	f.write(data)
	
	remaining = width * height - len(pixels)
	print(f"remaining pizels to fill: ", remaining)
	for _ in range(remaining):
		data += struct.pack('BBBB', 0, 0, 0, 32)
