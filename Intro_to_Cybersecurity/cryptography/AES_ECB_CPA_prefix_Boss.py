import requests
from base64 import b64decode
from urllib.parse import urljoin

BASE_URL = "http://challenge.localhost"
charset = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789|_{}-!?."
BLOCK_SIZE = 16  # AES block size
MAX_FLAG_LENGTH = 64  # upper bound guess

session = requests.Session()

def reset_db():
    """Reset the database (keep the flag only)."""
    session.post(urljoin(BASE_URL, "/reset"))

def post_secret(secret: bytes):
    """Submit a new secret (content) to the web app."""
    session.post(urljoin(BASE_URL, "/"), data={"content": secret.decode('latin1')})

def get_encrypted_backup() -> bytes:
    """Fetch the current encrypted backup (base64 -> bytes)."""
    response = session.get(urljoin(BASE_URL, "/"))
    b64_ct = response.text.split("<pre>")[1].split("</pre>")[0].strip()
    return b64decode(b64_ct)

def get_block(ct: bytes, block_index: int) -> bytes:
    """Return block `block_index` from ciphertext."""
    return ct[block_index * BLOCK_SIZE:(block_index + 1) * BLOCK_SIZE]

def recover_flag():
    known = b""
    print("[*] Starting flag recovery...")

    for i in range(MAX_FLAG_LENGTH):
        reset_db()

        # Determine how many "A"s to align next unknown byte at block boundary
        pad_len = BLOCK_SIZE - (len(known) % BLOCK_SIZE) - 1
        padding = b"A" * pad_len

        block_index = (len(known) + pad_len) // BLOCK_SIZE

        # Create dictionary of ciphertext blocks for every possible next byte
        block_dict = {}

        for c in charset:
            reset_db()
            guess = padding + known + bytes([c])
            post_secret(guess)
            ct = get_encrypted_backup()
            block_dict[get_block(ct, block_index)] = bytes([c])

        # Now get the actual ciphertext block for the unknown byte
        reset_db()
        post_secret(padding)
        ct = get_encrypted_backup()
        target_block = get_block(ct, block_index)

        # Lookup recovered byte
        recovered_byte = block_dict.get(target_block, None)
        if recovered_byte is None:
            print("[!] No match found — flag probably ended.")
            break

        known += recovered_byte
        print(f"[*] Recovered {len(known)} bytes: {known}")

    print(f"\n[+] Final recovered flag:\n{known.decode('latin1', errors='replace')}")

if __name__ == "__main__":
    recover_flag()
