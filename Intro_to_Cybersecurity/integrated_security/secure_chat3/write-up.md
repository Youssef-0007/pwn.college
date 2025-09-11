# Secure Chat 3 – Write-Up

### Overview

This challenge is part of the **Integrated Security module** on *pwn.college*. The service simulates a chat application where multiple users (Alice, Bob, Mallory, Sharon, etc.) interact. The goal is to extract a secret from encrypted chat traffic, even though “improved security” mechanisms have been layered onto the system since the earlier Secure Chat levels.

Two files define the behavior:

* `chat-server3.py`: Flask web app implementing user accounts, chat storage, encryption, and admin logic.
* `run3.py`: Orchestration harness that launches Alice, Bob, and Mallory (you), sets up the scenario, and drives the secure chat flow.

---

### Security Mechanisms in Place

1. **Account/Authentication Model**

   * Users can register and log in.
   * Alice (the “admin”) is special: her account is created from the local address and she is the one whose browser will execute Mallory’s messages.

2. **Encryption at Rest (Database)**

   * All chats are stored encrypted in the SQLite DB.
   * Encryption scheme: AES in ECB mode, with `app.secret_key` as the global key.
   * This prevents plaintext disclosure by simply dumping the DB, but ECB is deterministic and block-oriented, which leaks structure.

3. **Secure Chat Mode (Over-the-Wire)**

   * When Alice and Bob start a “secure chat,” they exchange Diffie–Hellman (DH) parameters inside chat messages.
   * Derived shared secret → truncated to 16 bytes → used as the AES key.
   * Mode again is AES-ECB, no integrity or MAC.
   * Vulnerable because DH parameters are not validated, and ECB remains malleable.

4. **Web Security Posture**

   * No output sanitization: chat messages are rendered directly into HTML.
   * Cookies are not marked HttpOnly.
   * No CSRF protections.

---

### Attack Surface

There are **multiple avenues** to exploit the system:

1. **Persistent XSS**

   * Mallory’s chat with Alice is guaranteed to be opened in Alice’s real browser by `run3.py`.
   * Mallory can embed JavaScript into a chat message.
   * The script executes in Alice’s origin, so it can:

     * Perform authenticated requests as Alice,
     * Inject or tamper with secure chat messages,
     * Read ciphertexts exchanged with Bob,
     * Relay data back to the attacker.

2. **SQL Injection**

   * Raw string interpolation is used in all queries (register, login, chat lookup, modify).
   * In principle, SQLi could grant Mallory admin privileges or access to encrypted rows directly.
   * But SQLite’s limitation of one statement per `execute` and the app’s logic make persistent exploitation trickier than simply leveraging XSS.

3. **Cryptographic Weakness (DH Manipulation)**

   * Alice posts a DH public value `A = g^a mod p`. Bob replies with his `B = g^b mod p`.
   * If Mallory injects `A = 1` (via XSS), the derived shared secret is forced to `s = 1^b mod p = 1`.
   * Key = 16 zero bytes, known to the attacker.
   * This allows decryption of subsequent AES-ECB ciphertexts exchanged between Alice and Bob.

4. **Padding Oracle & Block Manipulation**

   * Because of ECB’s deterministic block encryption, an attacker with control over inputs (like usernames or message contents) can craft chosen plaintexts to align blocks.
   * This enables byte-by-byte recovery of encrypted messages by matching ciphertext blocks against controlled trials.

---

### Variability in Solutions

Depending on how much of the system you exploit, there are different solution “levels”:

* **Level 1 (Web Exploitation only):**
  Use persistent XSS to act as Alice in her browser context. Directly exfiltrate ciphertexts from her chat with Bob, and manipulate her outbound messages.

* **Level 2 (Crypto Exploitation):**
  Combine XSS with a cryptographic attack: inject a weak DH parameter so Alice and Bob derive a predictable key. Then decrypt their “secure chat” traffic offline.

* **Level 3 (Database / ECB Oracle):**
  Even without touching DH, exploit ECB determinism:

  * Rename users or control chat text to create ciphertexts of chosen plaintexts.
  * Compare blocks to recover unknown portions of the encrypted message, byte by byte.
  * This requires careful padding management and block index tracking, but works entirely from the DB encryption behavior.

* **Level 4 (Hybrid):**
  Mix all of the above: SQLi or admin session tampering to gain broader control, then apply ECB oracle techniques to extract specific data.

---

### Key Takeaways

* **Security is layered, but brittle:**
  Even though the app encrypts messages and introduces a “secure chat” mode, it fails to validate inputs, sanitize outputs, or use secure cryptographic modes.

* **Web + Crypto = Break:**
  The combination of persistent XSS (a web bug) and DH parameter manipulation (a crypto bug) demonstrates how multiple weak layers can be chained into a practical exploit.

* **ECB remains dangerous:**
  Despite being “encrypted,” deterministic block ciphers without IVs leak structure and can be abused as oracles.

* **Variability is intentional:**
  The challenge is solvable by different approaches — pure XSS injection, DH parameter fixing, ECB oracle attacks, or SQLi. Each represents a different “security level” of exploitation.

---

✅ **In short:** Secure Chat 3 teaches that bolting “security” features onto an app (encryption, DH, “admin” users) doesn’t help if the fundamentals — output sanitization, cryptographic integrity, and safe DB queries — are missing. Different exploitation paths exist, each representing a higher or lower “security level” to bypass.


