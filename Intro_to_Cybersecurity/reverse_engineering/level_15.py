#!/bin/python3

import struct

header = (
	b"cIMG" +
	struct.pack("<I",1) +
	struct.pack("<H", 0x4f) +
	struct.pack("<I",0x18)
)


data = b" " * (0x768)


with open("solution_15.cimg", "wb") as f:
	f.write(header)
	f.write(data)
