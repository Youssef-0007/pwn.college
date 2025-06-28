#!/bin/python3

import struct

header = (
	b"cIMG" +
	struct.pack("<Q",2) +
	struct.pack("<H", 46) +
	struct.pack("<H", 23)
)

asu_maroon = (0x8C, 0x1D, 0x40)
pixel = struct.pack("BBB", *asu_maroon) + b"A"
data = pixel * (46 * 23)


with open("solution_20.cimg", "wb") as f:
	f.write(header)
	f.write(data)
