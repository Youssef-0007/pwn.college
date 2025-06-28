#!/bin/python3

import struct

header = (
	b"cIMG" +
	struct.pack("<I",2) +
	struct.pack("<I", 48) +
	b"\x16"
)

asu_maroon = (0x8C, 0x1D, 0x40)
pixel = struct.pack("BBB", *asu_maroon) + b"A"
data = pixel * (48 * 22)


with open("solution_19.cimg", "wb") as f:
	f.write(header)
	f.write(data)
