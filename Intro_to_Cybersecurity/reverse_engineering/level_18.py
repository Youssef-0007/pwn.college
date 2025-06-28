#!/bin/python3

import struct
width = 25
height = 11
nonspace_count = 275


header = (
	b"cIMG" +
	struct.pack("<I",1) +
	struct.pack("<Q", 46) +
	b"\x14"
)


data = b"A" * nonspace_count + b" " * ((46 * 20) -  nonspace_count)


with open("solution_18.cimg", "wb") as f:
	f.write(header)
	f.write(data)
