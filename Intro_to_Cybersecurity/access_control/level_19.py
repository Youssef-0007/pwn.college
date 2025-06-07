from pwn import *
import re

context.log_level = 'error'

p = process("/challenge/run")

# Regex for matching level and category names
RE_LEVEL_LINE = re.compile(rb"^\w{8}$")
RE_CATEGORY_LINE = re.compile(rb"^\w{3}$")
RE_QUESTION = re.compile(rb"level (\w+) and categories {(.*?)} (\w+) an Object with level (\w+) and categories {(.*?)}\?")

# === Step 1: Read until level list ===
levels = []
while True:
    line = p.recvline(timeout=0.1)
    if b"Levels" in line:
        break

# === Step 2: Parse 40 level names ===
for _ in range(40):
    level_line = p.recvline(timeout=0.05).strip()
    if RE_LEVEL_LINE.match(level_line):
        levels.append(level_line.decode())

# Map level name -> integer (higher index = higher level)
level_map = {name: 40 - i for i, name in enumerate(levels)}

# === Step 3: Parse categories ===
categories = []
while True:
    line = p.recvline(timeout=0.1).strip()
    if RE_CATEGORY_LINE.match(line):
        categories.append(line.decode())
    if len(categories) >= 5:
        break

# Category name -> bit position
cat_bit_map = {name: 1 << i for i, name in enumerate(categories)}

# Convert a category string to bitmask
def cat_mask(cat_str):
    return sum(cat_bit_map.get(c, 0) for c in cat_str.split(", ") if c)

# === Step 4: Answer 128 questions ===
for _ in range(128):
    q = p.recvuntil(b"?")
    m = RE_QUESTION.search(q)
    if not m:
        continue  # Skip malformed

    subj_lvl = level_map.get(m[1].decode(), -1)
    subj_cat = cat_mask(m[2].decode())
    action = m[3].decode()
    obj_lvl = level_map.get(m[4].decode(), -1)
    obj_cat = cat_mask(m[5].decode())

    if subj_lvl == -1 or obj_lvl == -1:
        continue

    if action == "read":
        allowed = subj_lvl >= obj_lvl and (subj_cat | obj_cat) == subj_cat
    else:
        allowed = subj_lvl <= obj_lvl and (subj_cat | obj_cat) == obj_cat

    p.sendline(b"yes" if allowed else b"no")

# === Step 5: Print final output (flag or error) ===
try:
    print(p.recvall(timeout=1).decode())
except EOFError:
    print("[!] Process ended early (bad answer or timeout)")
