#!/bin/python3

import struct

header = (
	b"{MAG" + 
	struct.pack("<Q", 1) +
	struct.pack("<I", 79) +
	struct.pack("<I", 24)
)


data = b" " * (79 * 24)


with open("solution_10.cimg", "wb") as f:
	f.write(header)
	f.write(data)
