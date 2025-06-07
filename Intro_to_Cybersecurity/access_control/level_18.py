from pwn import *
import re

context.log_level = 'error'  # Suppress output for speed

# Launch the challenge binary
p = process("/challenge/run")

# Levels and categories mapping
LEVELS = {"TS": 4, "S": 3, "C": 2, "UC": 1}
CATEGORY_BITS = {"NUC": 1, "NATO": 2, "ACE": 4, "UFO": 8}

def cat_mask(cat_str):
    """Convert category list string to bitmask."""
    if not cat_str.strip():
        return 0
    return sum(CATEGORY_BITS[cat] for cat in cat_str.split(", ") if cat in CATEGORY_BITS)

# Regex pattern for question
RE_Q = re.compile(rb"level (\w+) and categories {(.*?)} (\w+) an Object with level (\w+) and categories {(.*?)}\?")

# Warm up: skip intro messages fast
while True:
    line = p.recvline(timeout=0.01)
    if b"Categories:" in line:
        break

# Solve 20 questions
for _ in range(64):
    q = p.recvuntil(b"?")
    m = RE_Q.search(q)
    if not m:
        continue

    s_lvl = LEVELS[m[1].decode()]
    s_cat = cat_mask(m[2].decode())
    action = m[3].decode()
    o_lvl = LEVELS[m[4].decode()]
    o_cat = cat_mask(m[5].decode())

    if action == "read":
        allowed = s_lvl >= o_lvl and (s_cat | o_cat) == s_cat
    else:
        allowed = s_lvl <= o_lvl and (s_cat | o_cat) == o_cat

    p.sendline(b"yes" if allowed else b"no")

# Print the final output (should include the flag)
print(p.recvall(timeout=2).decode())
