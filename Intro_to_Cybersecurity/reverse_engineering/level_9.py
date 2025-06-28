#!/bin/python3

import sys
import struct

with open("solution_9.cimg", "wb") as out_file:
	out_file.write(b"[nnR")

	out_file.write(struct.pack("<I", 170))
