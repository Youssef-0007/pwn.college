
# 🧠 Pwn College — Intercepting Communication Module

This module guided us through a hands-on journey into the **real-world techniques** used to observe, disrupt, and manipulate digital communications. By gradually building from basic scanning and packet inspection to advanced **Man-in-the-Middle (MITM)** and **packet injection**, we acquired both offensive security techniques and a deep understanding of how protocols behave under attack.

---

## 📚 Topics Covered

The challenges spanned multiple layers of the network stack, including:

### 🔍 **1. Scanning & Network Discovery**

* **Ping-based discovery**
* **Full port scans with Nmap**
* **OS fingerprinting & service detection**

🛠 Tools: `ping`, `nmap`, `netcat`

---

### 🧪 **2. Traffic Monitoring & Sniffing**

* Live capture with **Wireshark**
* Passive inspection with **tcpdump** & **tshark**
* Extracting **credentials, flags, cookies** from unencrypted traffic

🛠 Tools: `Wireshark`, `tshark`, `tcpdump`, `Scapy.sniff()`

---

### 🍪 **3. Cookie & Credential Interception**

* Sniffing **session cookies** from HTTP traffic
* Understanding risks of **unencrypted authentication**
* Leveraging passive sniffing to **extract tokens**

---

### 🌐 **4. Network Configuration**

* IP and MAC spoofing
* Routing table manipulation
* Custom Ethernet and IP header crafting

🛠 Tools: `ip`, `ifconfig`, `Scapy`

---

### 🔥 **5. Firewall Evasion & Control**

* Configuring **inbound/outbound traffic rules**
* Bypassing simple filters
* Identifying weaknesses in misconfigured firewalls

🛠 Tools: `iptables`, `ufw`, `nmap` for rule testing

---

### 💥 **6. Denial of Service (DoS)**

* **UDP floods** using raw sockets
* **TCP exhaustion** via repeated handshake attempts
* Understanding stateless protocols for easy abuse

---

### 📡 **7. TCP Internals & Injection**

* Crafting full **3-way handshakes**
* Injecting data using **sequence & acknowledgment numbers**
* Spoofing **TCP packets** without completing handshake

🛠 Tool: `Scapy` (`IP()/TCP()/Raw()`), `netcat`

---

### 📮 **8. UDP Protocol & Spoofing Attacks**

* **Forging UDP packets** with spoofed IPs
* Launching **UDP reflection/amplification attacks**
* Explanation of **DNS reflection vulnerability**
* Understanding why **UDP is vulnerable** to spoofing

🛠 Tool: `Scapy`, Raw sockets

---

### 📬 **9. ARP Spoofing**

* Sending custom **ARP reply packets**
* Poisoning ARP cache of victim and gateway
* Setting up groundwork for MITM attacks

🛠 Tool: `Scapy`, `arping`

---

### 🕵️ **10. Intercepting & Manipulating Traffic**

* Full MITM attacks with forged ARP replies
* Capturing data streams in real-time
* Stealth injection into TCP flows by matching `seq/ack`
* Passive MITM: capturing traffic without altering the network

🛠 Tools: `Scapy.sendp()`, `sniff()`, Ethernet frame injection

---

## 🧠 Skills Acquired

| Concept              | Practical Skill                                                                     |
| -------------------- | ----------------------------------------------------------------------------------- |
| **Scanning**         | Detect open ports, live hosts, and services                                         |
| **Sniffing**         | Capture live traffic, extract sensitive data                                        |
| **Spoofing**         | MAC, IP, TCP, and ARP spoofing                                                      |
| **Injection**        | Craft and send TCP/UDP packets with controlled headers                              |
| **Firewall Evasion** | Analyze and bypass simple rule-based firewalls                                      |
| **DoS Attacks**      | Perform traffic floods and protocol-specific disruptions                            |
| **MITM Attacks**     | Intercept and modify live communications through ARP poisoning and packet injection |
| **Packet Crafting**  | Use Scapy to build Layer 2/3/4 packets manually                                     |

---

## 🧰 Tools & Utilities Used

| Tool          | Description                                            |
| ------------- | ------------------------------------------------------ |
| **Scapy**     | Crafting and sending packets (TCP, UDP, ARP, Ethernet) |
| **Wireshark** | GUI for packet inspection                              |
| **tcpdump**   | Terminal-based packet capture                          |
| **tshark**    | TUI analysis of capture files                          |
| **nmap**      | Network scanning and OS detection                      |
| **netcat**    | Port listener and connector                            |
| **iptables**  | Local firewall configuration                           |

---

## 📂 Challenge Examples

| Topic         | Challenge            | Description                                   |
| ------------- | -------------------- | --------------------------------------------- |
| Scanning      | `nmap_scan`          | Map open ports and determine service versions |
| Sniffing      | `cookie_theft`       | Capture and extract session cookies           |
| TCP Injection | `inject_tcp_payload` | Inject command after TCP handshake            |
| UDP Spoofing  | `spoof_dns_request`  | Exploit DNS server via UDP reflection         |
| ARP           | `arp_poison`         | Intercept traffic via ARP poisoning           |
| MITM          | `tcp_inject_mitm`    | Sniff TCP and stealthily inject data          |

---

## 🎓 Takeaways

By completing this module, you’ve gained a comprehensive **offensive security foundation** that blends:

* Protocol theory with real-world attacks
* Network tooling with packet-level control
* Passive observation and active manipulation

This knowledge is **directly applicable** to:

* Red teaming
* Penetration testing
* Defensive forensics
* Security tool development
