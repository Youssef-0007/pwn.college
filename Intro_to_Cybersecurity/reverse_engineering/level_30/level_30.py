with open("/challenge/flag.cimg", "rb") as f:
    data = bytearray(f.read())

# skip header (4 + 2 + 1 + 1 + 4 = 12 bytes)
print(f"before carfting the header --> width: {data[6]}, height: {data[7]}, number of directives: {data[8:12]}")
data[7] = 49
print(f"after carfting the header --> width: {data[6]}, height: {data[7]}, number of directives: {data[8:12]}")

i = 12


while i < len(data):
    if data[i] == 0x02 and data[i+1] == 0x00:
        data[i] = 0xC2  # low byte of 6331
        data[i+1] = 0xE8  # high byte of 6331
    i += 10  # each directive is 10 bytes


with open("patched_flag.cimg", "wb") as f:
    f.write(data)

