#!/bin/python3

import sys
import struct

with open("solution_8.cimg", "wb") as out_file:
	out_file.write(b"c:MG")

	out_file.write(struct.pack("<I", 51))
