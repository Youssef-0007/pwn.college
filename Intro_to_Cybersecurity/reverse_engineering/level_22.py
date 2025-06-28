#!/bin/python3

import struct

header = (
	b"cIMG" +
	struct.pack("<H",2) +
	b"\x04" +
	b"\x01"
)

pixels = [
	(170, 54, 112, ord('c')),
	(161, 129, 204, ord('I')),
	(1, 195, 53, ord('M')),
	(64, 46, 224, ord('G'))
]

data = b""
for r, g, b, ascii in pixels:
	data += struct.pack("BBBB", r, g, b, ascii)

with open("solution_22.cimg", "wb") as f:
	f.write(header)
	f.write(data)
