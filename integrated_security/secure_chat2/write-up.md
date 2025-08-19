## **Challenge Write-up — Fake DH Key Exchange Attack**

**Category:** Integrated Security (pwn.college – Intro to Cybersecurity)
**Topics:** Stored XSS, SQL Injection, Cryptography (Diffie–Hellman), AES, Web Exploitation

---

### **1. Challenge Overview**

The target is a secure chat web application used by Alice and Bob to exchange encrypted messages.
The chat:

* Uses **Diffie–Hellman key exchange** to derive a shared secret.
* Encrypts messages with **AES-ECB** using the shared key.
* Stores all messages encrypted in the database.

A separate challenge driver script (`run2.py`) automates Alice and Bob’s conversation:

* Alice says she heard Bob got the flag.
* Bob eventually sends the flag over the secure channel.

The attacker (us) controls **Mallory**, who can send messages to Alice before this conversation starts.

---

### **2. Vulnerabilities Identified**

#### **(a) SQL Injection**

Login queries are built directly from user input:

```python
db.execute(f"SELECT * FROM users WHERE username='{username}' and hashed_password='{hashed_password}'")
```

We can log in as any user with:

```
username=' OR username LIKE 'bob%'--
password=anything
```

---

#### **(b) Stored XSS**

Messages are rendered in HTML without sanitization:

```python
contents_html = "\n<br>\n".join(contents.splitlines())
```

No escaping of `<script>` tags means JavaScript can run in Alice’s browser.

---

#### **(c) Weak Crypto Implementation**

* Diffie–Hellman values are sent as **plaintext messages** in chat:

  * Alice: `Let's chat securely over DHE-AES: <A>.`
  * Bob: `Hey Alice, sure: <B>.`
* AES key is derived directly from the shared secret as:

```python
key = dh_s.to_bytes(256, "big")[:16]
```

* If both sides’ public values are set to `1`, the shared secret `dh_s` = 1, so **AES key** is just 16 bytes of zeros ending in `01`.

---

### **3. Exploitation Plan**

We realized that **if we control both DH values (`A` and `B`)**, we can force both sides to derive a **predictable shared key** = `1` and decrypt all messages.

The main obstacle:

* We only directly control Mallory.
* Bob’s messages are generated automatically by the challenge script.
* We need to inject **Alice’s `A=1`** *before* Bob’s DH handler runs, and then inject **Bob’s `B=1`** only after Alice’s value is posted.

---

### **4. Attack Execution**

**Step 1 – Log in as Mallory & Bob (SQLi)**
We used SQL injection to grab valid session cookies for both accounts.

**Step 2 – Inject looping-XSS into Alice’s chat**
We sent Mallory → Alice a `<script>` that runs in Alice’s browser and posts:

```
Hey Bob, I need to chat with you about something important. Let's chat securely over DHE-AES: 1.
```

every 200 ms. This ensures `A=1.` is always the first match for Bob’s DH regex.

**Step 3 – Trigger conversation**
We posted `"I heard someone shared the flag with Bob!"` to start Alice’s scripted DH/AES sequence.

**Step 4 – Wait for `dh_A=1.` to appear**
Bob’s script polled `/chat/alice` until Alice’s `A=1.` appeared, confirming the XSS fired.

**Step 5 – Spam Bob’s `B=1.` reply**
Once Alice’s value was posted, we repeatedly posted:

```
Hey Alice, sure: 1.
```

every poll cycle to ensure Alice’s DH regex picks our `B=1.`.

**Step 6 – Derive the key and decrypt**
With both public values set to `1`, the shared secret is `1`, so:

```python
key = (1).to_bytes(256, "big")[:16]
```

We used this key to AES-decrypt every ciphertext in the chat until we found the message containing `pwn.college{...}`.

---

### **5. Final Script**

Our final Python exploit:

* Logs in as Mallory & Bob via SQLi.
* Injects looping-XSS in Alice’s chat.
* Waits for forged `A=1.`.
* Spams Bob’s `B=1.`.
* Decrypts all AES ciphertexts using key from shared secret `1`.
* Prints the flag once found.

---

### **6. Key Points Learned**

* **Stored XSS** can directly alter cryptographic protocol parameters if the protocol messages are handled in the browser.
* **DH public values are not authenticated** here, so a man-in-the-middle can replace them with weak values.
* **AES-ECB with predictable keys** offers no confidentiality.
* Race conditions in multi-user flows can be solved by **spamming values** to dominate the first regex match.

---

### **7. Flag**

```
pwn.college{<redacted>}
```

---
