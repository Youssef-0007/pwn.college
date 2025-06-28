with open("/challenge/flag.cimg", "rb") as f:
    data = bytearray(f.read())

# skip header (4 + 2 + 1 + 1 + 4 = 12 bytes)
# print(f"before crafting the header --> width: {data [6]}, height: {data [7]}, number of directives: {data[8:12]}")

flag = data[:12]
i = 12
directives = 0

while i < len(data):
    # print(f"[-] Index = {i}, data : {data[i]}")
    # edit the id of the directive handle_3
    if data[i] == 0x06 and data[i + 1] == 0x00:
        i += 3
        continue
    if data[i] == 0x07 and data[i + 1] == 0x00:
        i += 6
        continue
    if data[i] == 0x02 and data[i + 1] == 0x00:
        directives += 1
        flag += data[i:i + 2]  # first append directive code
        flag += data[i + 2:i + 4]  # second append the x, y positions
        flag += data[i + 4:i + 6]  # third append the width and the height
        w = data[i + 4]
        h = data[i + 5]
        if (w == 0 or h == 0):
            print(f"[x] wrong dimensions at index = {i}, width = {w}, height = {h}")
            break
        data_size = (w * h * 4)
        flag += data[i + 6:i + 6 + data_size]
        print(f"[-] x: {data[i + 2]}, y: {data[i + 3]}, w: {data[i + 4]}, h: {data[i + 5]}, payload: {data[i + 6:i + 6 + data_size]}")
        i += (6 + data_size)
    else:
        print(f"[+] Unusual directive code: {data[i:i + 2]}")

print(f"number of directives: {directives}")
directives = directives.to_bytes(4, 'little')
flag[8:12] = directives

with open("flag.cimg", "wb") as f:
    f.write(flag)
