# Cryptography – Intro to Cybersecurity @ pwn.college

This repository contains my solutions and learning notes for the **Cryptography module** from the **Intro to Cybersecurity** course on [pwn.college](https://pwn.college). This module dives deep into real-world cryptographic vulnerabilities and how attackers exploit them — providing hands-on challenges that go far beyond theory.

---

## 🔐 Topics Covered

- **XOR-based encryption**: Fundamentals, one-time and many-time pad attacks.
- **AES in ECB mode**:
  - Chosen-plaintext attacks (CPA)
  - Byte-at-a-time ECB decryption
  - Oracle-based flag recovery
- **AES in CBC mode**:
  - Bit-flipping attacks
  - Padding oracle attacks (POA)
  - Full plaintext recovery using POA
  - CBC encryption via POA – a reverse challenge
- **Public-key cryptography**:
  - Diffie-Hellman Key Exchange (DHKE)
  - RSA encryption and decryption
  - RSA signature manipulation
- **Hash functions**:
  - Brute-force preimage and collision attacks (SHA1, SHA2)
- **TLS Simulation**:
  - Building a simplified TLS handshake
  - Secure key exchange
  - AES session encryption and message integrity

---

## 📌 Highlights & Lessons Learned

- Cryptographic primitives like **AES**, **DHKE**, and **RSA** are not inherently secure — how you use them matters most.
- I implemented real **padding oracle attacks** to decrypt ciphertext and even encrypt new messages, using only a decryption oracle.
- Learned how **CBC mode** is vulnerable to bit-flipping tampering, and how a simple XOR can change plaintext post-decryption.
- Built understanding of **TLS** by simulating a complete key exchange, session encryption, and certificate signing process using learned primitives.
- Gained insight into the mindset of cryptanalysts and attackers by breaking crypto through misconfigurations and logic flaws — not brute force.

---

## ⚠️ Disclaimer

These solutions are for **educational purposes only**. I encourage you to **attempt each challenge yourself** before reviewing the code or write-ups. Cryptography is best learned by doing — and pwn.college excels at making that possible.

---

## 📂 Structure

Each subdirectory corresponds to a specific challenge, with:
- Source code/scripts used
- Notes explaining the attack logic
- Results or flags (if applicable)

---

## 🙌 Credits

Thanks to the [pwn.college](https://pwn.college) team for offering a high-quality, CTF-style cryptography course that teaches real offensive techniques in a legal and safe environment.

