## 🔐 AES-ECB-CPA Prefix Boss – Challenge Write-up (Optimized)

### 📜 Challenge Description

In this web-based AES challenge, a flag is stored in a temporary SQLite database and encrypted using **AES in ECB mode**. Your job is to **recover the flag** through a **chosen-plaintext attack**, with a twist: your input is **appended after** the secret, not prepended.

You can:

* `POST /` to add your own content
* `POST /reset` to reset the DB to only contain the flag
* `GET /` to fetch a base64-encoded encrypted dump of the DB

---

### 🧠 Exploit Strategy: ECB Prefix Attack

AES in ECB mode leaks information when:

* Input data has predictable structure
* Repeated blocks generate repeated ciphertext blocks

#### Key Challenge: Flag is First

Unlike the classic Oracle ECB challenge, the secret (flag) is inserted **before your content** in the database. You can’t directly control alignment — you **append** to the flag row.

#### But:

By carefully adjusting the **length of your input**, you can cause the unknown flag byte to **fall at the end of an AES block**, where it can be brute-forced.

---

### 🚀 Optimization: Reduce Guess Space

Instead of trying all 256 possible byte values, we **limit our guesses to a known charset**:

```
abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}-!?.
```

This:

* Reduces per-byte brute-force guesses from 256 → 66
* Speeds up the attack \~4x
* Reduces server load and response time

---

### 📋 Steps to Recover the Flag

1. **Reset the DB**

   * Keeps only the secret flag in the DB

2. **Pad Your Input**

   * Align the target unknown flag byte to fall at the end of a block

3. **Get Reference Cipher Block**

   * Submit just the padding
   * Capture the ciphertext block where the flag byte appears

4. **Brute-force from CHARSET**

   * Append each possible character to padding + known\_flag
   * Compare ciphertext blocks
   * If they match → you've found the correct byte!

5. **Repeat Until Done**

   * Continue until no more matches — padding or end of flag

---

### ✅ Output

The script gradually prints recovered bytes:

```
[*] Recovered 1 bytes: b'f'
[*] Recovered 2 bytes: b'fl'
...
[+] Final recovered flag:
flag{ECB_was_never_meant_for_storage}
```

---

### 📌 Takeaways

* **AES-ECB should never be used for sensitive or structured data**, even with random keys.
* Prefix-style ECB oracles can be broken with **byte-alignment tricks** and **block comparison**.
* **Restricting guess space** with known character sets is an easy and powerful optimization.
