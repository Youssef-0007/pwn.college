#!/bin/python3

import struct

header = (
	b"(Nnr" + 
	struct.pack("<H", 1) +
	struct.pack("<I", 64) +
	struct.pack("<I", 12)
)


data = b" " * (64 * 12)


with open("solution_11.cimg", "wb") as f:
	f.write(header)
	f.write(data)
