#!/bin/python3

import struct

header = (
	b"cIMG" +
	struct.pack("<I",1) +
	struct.pack("<I", 40) +
	struct.pack("<I",14)
)


data = b" " * (40 * 14)


with open("solution_14.cimg", "wb") as f:
	f.write(header)
	f.write(data)
