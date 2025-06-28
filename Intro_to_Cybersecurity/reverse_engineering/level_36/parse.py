with open("flag.cimg", "rb") as f:
    data = bytearray(f.read())
    
i = 12
while i < len(data):
    if data[i] == 0x02 and data[i + 1] == 0x00:
        print(f"x: {data[i + 2]}, y: {data[i + 3]}, w: {data[i + 4]}, h: {data[i + 5]}, payload: {data[i + 6 : i + 10]}")
        i += 10
        continue
    else:
        print(f"directive not 2: {data[i]}")
        i+= 1
