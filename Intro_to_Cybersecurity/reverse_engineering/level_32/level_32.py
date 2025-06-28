with open("/challenge/flag.cimg", "rb") as f:
    data = bytearray(f.read())

# skip header (4 + 2 + 1 + 1 + 4 = 12 bytes)
print(f"before carfting the header --> width: {data[6]}, height: {data[7]}, number of directives: {data[8:12]}")

data[6] = 112	# edith the width
data[7] = 32	# edit the height

print(f"after carfting the header --> width: {data[6]}, height: {data[7]}, number of directives: {data[8:12]}")

i = 12

while i < len(data):
    print(f"index = {i}, data at i: {data[i]}")
    # edit the id of the directive handle_3
    if data[i] == 0x03 and data[i +1] == 0x00:
        i += 60
        
    if (data[i] == 0x04 and data[i +1] == 0x00):
        data[i + 6] = x	# edit the base_x
        data[i + 7] = y	# edit the base_y
        
        x += 7
        if x >= 112:
            x = 0
            y += 8
        
        i += 8
        continue
        
    i += 1

with open("patched_flag.cimg", "wb") as f:
    f.write(data)

