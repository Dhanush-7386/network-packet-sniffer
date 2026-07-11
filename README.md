
# 🛡️ Custom Layer 2-4 Network Packet Sniffer

![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%20%2F%20Ubuntu-orange.svg)
![Focus](https://img.shields.io/badge/Focus-Network%20Security%20%2F%20DPI-brightgreen.svg)
![Status](https://img.shields.io/badge/Status-Completed-success.svg)

A low-level network diagnostic and **Deep Packet Inspection (DPI)** tool built from scratch using Python's native `socket` and `struct` modules. 

Unlike standard automated scripts that rely on high-level libraries (like Scapy), this project bypasses pre-built abstractions to directly interact with Linux network interface cards (`NIC`). It manually unpacks raw binary byte streams to demonstrate real-time data **de-encapsulation across the OSI Model layers**.

---

## 🏗️ Architecture & Protocol De-encapsulation Flow

The sniffer intercepts raw binary frames from the wire and systematically peels back protocol headers from the Data Link layer up to the Application layer:

```text
[ Raw Network Wire ]
       │
       ▼
┌──────────────────────────────────────────────┐
│ Layer 2: Data Link (Ethernet Frame)          │ ──> Extracts Source/Dest MAC Addresses & Protocol ID
└──────────────────────────────────────────────┘
       │ (If Protocol == 0x0800 / IPv4)
       ▼
┌──────────────────────────────────────────────┐
│ Layer 3: Network (IPv4 Header)               │ ──> Extracts Source/Dest IP Addresses & Time-To-Live (TTL)
└──────────────────────────────────────────────┘
       │ (If Protocol == 6 / TCP)
       ▼
┌──────────────────────────────────────────────┐
│ Layer 4: Transport (TCP Header)              │ ──> Extracts Source/Dest Port Numbers (Identifies Port 80 HTTP)
└──────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────┐
│ Layer 7: Application (Raw Payload)           │ ──> Runs Regex DPI Engine to hunt for plaintext credentials
└──────────────────────────────────────────────┘

```

---

## 🚀 Key Features

* **Raw Socket Binding:** Hooks directly into the Linux kernel network stack using `AF_PACKET` sockets, operating in promiscuous mode to capture ambient wire traffic.
* **Low-Level Binary Parsing:** Utilizes Python's `struct` module to unpack network byte order (Big-Endian) binary streams into readable data types.
* **Deep Packet Inspection (DPI):** Features an automated regular expression hunting engine that scans HTTP payloads in real-time for sensitive unencrypted authentication parameters (e.g., `username`, `password`, `login`, `bearer`).
* **Automated Evidence Logging:** Immediately flags suspicious payloads in the terminal and logs raw capture strings to a local file (`suspicious_traffic.log`) for forensic review.

---

## 🛠️ Tech Stack & Tools

| Category | Technology / Tool | Purpose |
| --- | --- | --- |
| **Language** | Python 3 | Core script logic and socket programming |
| **System Libraries** | `socket`, `struct`, `re`, `sys` | Raw network access and binary data unpacking |
| **Environment** | Ubuntu Linux / POSIX | Requires Linux kernel packet-level access |
| **Verification Tools** | Wireshark, `curl`, `tcpdump` | Lab simulation and packet validation |

---

## 📖 Key Concepts Mastered

1. **The OSI Encapsulation Model:** Hands-on experience mapping theoretical network layers to real-world byte structures.
2. **Network Byte Order (Endianness):** Managing the conversion between system hardware memory (Little-Endian) and network transmission standards (Big-Endian) using strict formatting tokens (`!`).
3. **Offensive & Defensive Awareness:** Practical demonstration of how unencrypted legacy protocols (HTTP) expose system infrastructure to Man-in-the-Middle (MitM) credential sniffing, reinforcing the critical need for uniform TLS/HTTPS enforcement.

---

## 🚦 Installation & Lab Usage

> **⚠️ Legal & Ethical Disclaimer:** This tool is intended for educational purposes, defensive system understanding, and authorized security research only. Do not run this tool on networks or systems you do not personally own or have explicit, documented permission to audit.

### Prerequisites

* A Linux-based operating system (Ubuntu/Debian recommended).
* Root / Administrative privileges (required to open raw network sockets).

### 1. Clone the Repository

```bash
git clone [https://github.com/Dhanush-7386/network-packet-sniffer.git](https://github.com/Dhanush-7386/network-packet-sniffer.git)
cd network-packet-sniffer

```

### 2. Start the Packet Sniffer

Launch the tool with administrative privileges so it can bind to the network interface card:

```bash
sudo python3 sniffer.py

```

### 3. Simulate an Unencrypted Login Attack (In a Separate Terminal)

Open a second terminal window and use `curl` to send simulated POST credentials over unencrypted HTTP:

```bash
curl -X POST [http://httpbin.org/post](http://httpbin.org/post) -d "username=admin&password=SuperSecretPassword123"

```

### 4. Expected Terminal Output

Upon intercepting the packet, the DPI engine will fire and output the captured credentials:

```text
[*] Initializing Raw Socket Sniffer...
[*] Listening for traffic on all network interfaces...
[*] Press Ctrl+C to stop the capture.
============================================================
[TCP] 192.168.1.15:54321 -> 50.17.200.1:80 | TTL: 64 | Payload: 215 bytes

!!!!!!!!!!!!!!!!!!!! SENSITIVE DATA DETECTED !!!!!!!!!!!!!!!!!!!!
POST /post HTTP/1.1
Host: httpbin.org
User-Agent: curl/7.88.1
Accept: */*
Content-Length: 48
Content-Type: application/x-www-form-urlencoded

username=admin&password=SuperSecretPassword123
============================================================

```

---

## 🔒 Security Notice

To prevent accidental data leakage, ensure that `*.log` files are ignored by your version control system. A `.gitignore` file is included in this repository by default.

```
