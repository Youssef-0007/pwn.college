#!/bin/python3

import struct

header = (
	b"<NMg" +
	struct.pack("<I",1) +
	struct.pack("<Q", 0x2e) +
	b'\x14'
)


data = b"\x00" * 0x398


with open("solution_12.cimg", "wb") as f:
	f.write(header)
	f.write(data)
