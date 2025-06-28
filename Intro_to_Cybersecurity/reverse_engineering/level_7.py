#!/bin/python3

import sys
import struct

with open("solution_7.cimg", "wb") as out_file:
	out_file.write(b"cm6e")

	out_file.write(struct.pack("<I", 135))
