#!/bin/python3

with open("desired_output.raw", "rb") as f:
	raw_data = f.read()

with open("desired_output.txt", "w", encoding="utf-8") as f:
	f.write(raw_data.decode("utf-8", errors="ignore"))
