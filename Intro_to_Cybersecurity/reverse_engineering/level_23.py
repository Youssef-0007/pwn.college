#!/bin/python3

import struct

header = (
	b"cIMG" +
	struct.pack("<H",2) +
	b"\x04" +
	b"\x01"
)

pixels = [
	(154, 172, 10, ord('c')),
	(53, 95, 225, ord('I')),
	(132, 94, 67, ord('M')),
	(205, 36, 86, ord('G'))
]

data = b""
for r, g, b, ascii in pixels:
	data += struct.pack("BBBB", r, g, b, ascii)

with open("solution_23.cimg", "wb") as f:
	f.write(header)
	f.write(data)
