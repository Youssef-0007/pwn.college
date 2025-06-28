#!/bin/python3

import struct
width = 25
height = 11
nonspace_count = 275


header = (
	b"cIMG" +
	struct.pack("<I",1) +
	struct.pack("<H", width) +
	struct.pack("<I",height)
)


data = b"A" * nonspace_count + b" " * (width * height * nonspace_count)


with open("solution_17.cimg", "wb") as f:
	f.write(header)
	f.write(data)
