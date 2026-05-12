# SpectreScan

> A modular Nmap-inspired network reconnaissance framework built in Python.

SpectreScan is a lightweight and extensible network scanner designed for cybersecurity learning, reconnaissance automation, and network analysis. The project supports asynchronous TCP scanning, subnet discovery, SYN scans using Scapy, optional JSON reporting, and a plugin-based architecture.

---

# Features

- Asynchronous TCP scanning
- CIDR subnet/network scanning
- SYN (Half-Open) scanning using Scapy
- Banner grabbing and service detection
- Lightweight modular architecture
- Plugin support
- Custom scripting engine
- Basic OS fingerprinting
- Optional JSON report generation
- Custom port range scanning
- Resume-worthy cybersecurity project

---

# Project Structure

```text
SpectreScan/
│
├── core/
│   ├── scanner.py
│   ├── syn.py
│   ├── banner.py
│   └── reporter.py
│
├── plugins/
│   ├── http_plugin.py
│   └── ssh_plugin.py
│
├── main.py
├── requirements.txt
├── .gitignore
└── README.md
```

---

# Installation

## Clone Repository

```bash
git clone https://github.com/yourusername/SpectreScan.git
cd SpectreScan
```

## Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

# Usage

## Scan a Single Host

```bash
python main.py 127.0.0.1
```

---

## Scan an Entire Network

```bash
python main.py 192.168.1.0/24
```

---

## Custom Port Range

```bash
python main.py 192.168.1.0/24 --start 1 --end 5000
```

---

## SYN Scan

```bash
sudo python main.py 192.168.1.0/24 --syn
```

---

## Save Scan Results

```bash
python main.py 192.168.1.0/24 --save results.json
```

---

# Example Output

```text
[+] 192.168.1.1:22/tcp OPEN SSH-2.0-OpenSSH_9.3
[+] 192.168.1.1:80/tcp OPEN HTTP/1.1 200 OK
[+] 192.168.1.5:445/tcp OPEN SMB
```

---

# Technologies Used

- Python 3
- asyncio
- Scapy
- Rich
- Socket Programming

---

# Planned Features

- UDP scanning
- Advanced OS fingerprinting
- CVE enrichment
- Web dashboard
- Docker support
- Network topology visualization
- Distributed scanning agents
- Stealth scan profiles
- Service version fingerprinting

---

# Scripting Engine

SpectreScan includes a lightweight custom scripting engine inspired by the Nmap Scripting Engine (NSE).

The scripting system allows developers to create custom reconnaissance and enumeration modules that can run automatically against discovered services.

Example:

```python
@register("http")
def detect_admin_panel(target, port):
    pass
```

This architecture allows SpectreScan to become extensible and modular instead of remaining a simple port scanner.

---

# OS Detection

SpectreScan includes basic operating system fingerprinting using:

- TTL analysis
- TCP response behavior
- Window size analysis
- Packet fingerprinting

The scanner attempts to estimate whether a host is running:

- Linux
- Windows
- BSD
- Cisco IOS

---

# Why SpectreScan?

Most beginner network scanners only perform basic socket-based port scanning.

SpectreScan was designed to go beyond that by implementing:

- Concurrent scanning
- Packet crafting
- Extensible architecture
- Reconnaissance automation
- Modular plugin support

The goal is to build a practical reconnaissance framework inspired by tools like Nmap while maintaining a lightweight and customizable codebase.

---



# Legal Disclaimer

This project is intended strictly for:

- Educational purposes
- Authorized security testing
- Personal lab environments
- CTF platforms like HackTheBox and TryHackMe

Do not scan systems or networks without explicit authorization.

---

# Author

Deepanshu

