# SpectreScan v2

> A modular Nmap-inspired network reconnaissance framework built in Python with interactive UI and customizable scan modes.

SpectreScan is an extensible network scanner designed for cybersecurity learning, reconnaissance automation, and network analysis. It supports asynchronous TCP scanning, SYN scanning, subnet discovery, OS fingerprinting, version detection, and a plugin-based architecture with Nmap-style scripting.

---

## Features

- **Asynchronous TCP connect scanning** with progress tracking
- **SYN (half-open) scanning** using Scapy (requires root)
- **UDP scanning** support
- **CIDR subnet/network scanning** with ARP discovery
- **OS fingerprinting** via TTL analysis with confidence percentages
- **Service/version detection** with probe-based banner grabbing
- **Interactive UI mode** for easy scan configuration
- **Nmap-style scripting engine** with registered script categories
- **Plugin system** with automatic service matching
- **JSON report generation** with full scan metadata
- **Progress bars** for long-running scans
- **Nmap-like results table** with host, port, service, and OS columns
- **Root-aware scan mode selection** (SYN if root, TCP if unprivileged)
- **Exposed .git detection** via built-in HTTP scripts

---

## Installation

### Clone Repository

```bash
git clone https://github.com/yourusername/SpectreScan.git
cd SpectreScan
```

### Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Usage

### Interactive Mode (Recommended)

Launch the interactive menu to configure your scan:

```bash
python main.py -i
```

This will prompt you for:
- Target (IP or CIDR)
- Port range/list
- Scan type (auto, tcp, syn, udp, all)
- Service version detection
- OS detection
- Script execution
- Plugin execution
- Timeout and concurrency settings

### Command-Line Mode

#### Scan a Single Host

```bash
python main.py 127.0.0.1
```

#### Scan an Entire Network

```bash
python main.py 192.168.1.0/24
```

#### Custom Port Range

```bash
python main.py 192.168.1.0/24 -P 22,80,443,1000-2000
```

#### TCP Connect Scan (Non-Root)

```bash
python main.py 127.0.0.1 -M tcp -sV
```

#### SYN Scan with OS Detection (Requires Root)

```bash
sudo python main.py 127.0.0.1 -M syn -O -sV
```

#### UDP Scan

```bash
python main.py 127.0.0.1 -sU -P 53,123,161
```

#### Run with Scripts and Plugins

```bash
python main.py 127.0.0.1 -sV -sC -p
```

#### Aggressive OS Fingerprinting (Requires Root)

```bash
sudo python main.py 127.0.0.1 --aggressive-fingerprinting -O
```

#### Check for CVEs in Detected Services

```bash
python main.py 127.0.0.1 -sV --check-cve
```

#### Use Timing Template for Slower, Stealthier Scan

```bash
python main.py 127.0.0.1 -T1  # Sneaky profile
python main.py 127.0.0.1 -T4  # Aggressive profile
```

#### Route Scan Through Proxy

```bash
python main.py 127.0.0.1 --proxy socks5://127.0.0.1:1080
```

#### Combine Multiple Advanced Features

```bash
sudo python main.py 192.168.1.0/24 -M syn -O --aggressive-fingerprinting -sV --check-cve -sC -p -T3 -o scan_report.json
```

---

## Command-Line Options

### Modes

- `-i, --interactive` — Launch interactive menu mode

### Target Specification

- `target` — Target IP or CIDR

### Host Discovery

- `-n, --no-discovery` — Skip discovery and scan target directly

### Scan Types

- `-M, --scan-type` — `auto` (default), `tcp`, `syn`, `udp`, or `all`
  - `auto` uses SYN if root, otherwise TCP
- `-sS, --syn` — TCP SYN scan (requires root)
- `-sU, --udp` — UDP scan

### Timing Templates (Nmap-style)

- `-T, --timing-template` — Scan speed (default: `3`)
  - `0` — Paranoid: Very slow, stealthy (5min timeout, 1 concurrent)
  - `1` — Sneaky: Slow, less detectable (1min timeout, 2 concurrent)
  - `2` — Polite: Reduced network load (5s timeout, 50 concurrent)
  - `3` — Normal: Balanced speed/stealth (1s timeout, 500 concurrent) **[default]**
  - `4` — Aggressive: Fast scanning (500ms timeout, 1000 concurrent)
  - `5` — Insane: Very fast, high network load (100ms timeout, 2000 concurrent)

### Service/Version Detection

- `-sV, --version` — Probe open ports for service/version info
- `-O, --os` — Enable OS detection via TTL (requires root)
- `--aggressive-fingerprinting` — Advanced OS fingerprinting using:
  - TCP window size analysis
  - SYN cookies detection
  - IP options response analysis
  - ICMP response patterns

### Vulnerability Assessment

- `--check-cve` — Check detected services for known CVEs from NVD database
- Automatically correlates service versions with CVE data

### Scripts & Plugins

- `-sC, --scripts` — Run built-in Nmap-style scripts
- `-C, --script-categories` — Comma-separated script categories (default: `default`)
- `-p, --plugins` — Run service plugins from `plugins/` folder

### Performance

- `-P, --ports` — Port range/list, e.g. `22,80,443,1000-2000` (default: `1-65535`)
  - **Full TCP port scan by default**; expect a longer scan time
- `--timeout` — Connection timeout in seconds (overrides timing template)
- `-c, --concurrency` — Maximum concurrent probes (overrides timing template)

### Advanced Options

- `--proxy PROXY_URL` — Route traffic through proxy
  - Supports `http://host:port`
  - Supports `https://host:port`
  - Supports `socks5://host:port`
- Environment variables: `PROXY_HTTP`, `PROXY_HTTPS`, `PROXY_SOCKS5`

### Output

- `-o, --save FILE` — Save JSON report to file
- `-H, --help-brief` — Display compact help with all options

---

## Configuration

SpectreScan supports environment-based configuration via `.env` file. Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

### Environment Variables

```bash
# Proxy Settings
PROXY_HTTP=http://proxy.company.com:8080
PROXY_HTTPS=https://proxy.company.com:8080
PROXY_SOCKS5=socks5://127.0.0.1:1080

# CVE Database
CVE_API_KEY=your_nvd_api_key_here
NVD_API_URL=https://services.nvd.nist.gov/rest/json/cves/2.0

# API Keys for Service Detection
SHODAN_API_KEY=
CENSYS_API_KEY=

# Scan Defaults
DEFAULT_SCAN_TYPE=auto
DEFAULT_TIMEOUT=1.0
DEFAULT_CONCURRENCY=500

# Logging
LOG_LEVEL=INFO
LOG_FILE=
```

---

## Advanced Features

### 1. Timing Templates

SpectreScan implements Nmap-style timing templates for different scan profiles:

```bash
# Paranoid (IDS evasion)
python main.py 192.168.1.1 -T0

# Sneaky (stealthy)
python main.py 192.168.1.1 -T1

# Polite (network-friendly)
python main.py 192.168.1.1 -T2

# Normal (default, balanced)
python main.py 192.168.1.1 -T3

# Aggressive (fast scanning)
python main.py 192.168.1.1 -T4

# Insane (maximum speed)
python main.py 192.168.1.1 -T5
```

Each template automatically configures timeout, concurrency, and retry settings.

### 2. Aggressive OS Fingerprinting

Beyond TTL analysis, use advanced fingerprinting techniques:

```bash
sudo python main.py 192.168.1.1 --aggressive-fingerprinting
```

Analyzes:
- **TCP Window Size** — OS-specific window size patterns
- **SYN Cookies** — Linux-specific SYN cookie implementation
- **IP Options** — Varied response handling by different OS
- **ICMP Patterns** — ICMP echo reply behavior

### 3. CVE Integration

Automatically check detected services for known vulnerabilities:

```bash
python main.py 192.168.1.1 -sV --check-cve
```

Requires NVD API key (free from NIST):
1. Register at https://nvd.nist.gov/developers/request-an-api-key
2. Add to `.env`: `CVE_API_KEY=your_key_here`

Results include:
- CVE IDs for detected service versions
- Severity levels (Critical, High, Medium, Low)
- CVSS scores

### 4. Proxy Routing

Route scans through HTTP, HTTPS, or SOCKS5 proxies:

```bash
# HTTP proxy
python main.py 192.168.1.1 --proxy http://proxy.company.com:8080

# SOCKS5 proxy
python main.py 192.168.1.1 --proxy socks5://127.0.0.1:1080
```

Or set environment variables:

```bash
export PROXY_HTTP=http://proxy.company.com:8080
python main.py 192.168.1.1
```

### 5. Advanced Nmap-Style Scripting

SpectreScan includes Nmap NSE-inspired scripts:

```bash
python main.py 192.168.1.1 -sC
```

Built-in scripts by category:
- **ssl-cert** — Extract SSL certificate information
- **http-enum** — Enumerate common HTTP paths
- **smb-os-discovery** — SMB OS detection
- **dns-brute** — DNS subdomain enumeration
- **mysql-info** — MySQL version and configuration
- **postgres-query** — PostgreSQL information
- **redis-info** — Redis server information

Create custom Lua-style scripts in `scripts/` directory:

```lua
-- scripts/my-custom-scan.lua
-- @name my-custom-scan
-- @description Custom reconnaissance script
-- @categories discovery
-- @author YourName

function run()
    -- Custom script logic here
    return "result"
end
```

---

SpectreScan includes NSE-style scripts that run automatically:

### HTTP Scripts

- **http-title** — Extract HTML page title
- **http-methods** — Probe allowed HTTP methods
- **http-git** — Detect exposed `.git` repositories

### FTP Scripts

- **ftp-anon** — Check for anonymous FTP access

### SSH Scripts

- **ssh-auth-methods** — Report available SSH authentication methods

### Script Categories

- `default` — Runs on common ports automatically
- `http` — HTTP-specific scripts
- `ssh` — SSH-specific scripts

---

## Plugins

Plugins are Python modules in the `plugins/` folder that extend scanner functionality.

### Creating a Plugin

Create `plugins/myservice_plugin.py`:

```python
PLUGIN_NAME = "myservice_plugin"
PLUGIN_CATEGORIES = ["default", "myservice"]
PORTS = [1234]
SERVICE_KEYWORDS = ["MYSVC"]

def run(target, port, banner):
    # Custom probing logic
    return {"result": "data"}
```

### Existing Plugins

- **http_plugin.py** — HTTP server detection and info extraction
- **ssh_plugin.py** — SSH banner and capability detection

---

## OS Detection

SpectreScan identifies operating systems using TTL (Time-To-Live) analysis from TCP responses:

- **Linux** — TTL ≤ 64 (default 64)
- **Windows** — TTL around 128
- **Cisco/Network Device** — TTL around 255

**Note:** OS detection requires root privileges to craft raw packets. Confidence is calculated based on TTL deviation from known baselines.

Examples:
- `Linux (100%)` — Perfect match (TTL = 64)
- `Linux (92%)` — Close match (TTL = 66)
- `Windows (87%)` — Reasonable match (TTL = 124)

---

## Project Structure

```
SpectreScan/
│
├── core/
│   ├── scanner.py          # Async TCP connect scanning
│   ├── syn.py              # SYN scanning with Scapy
│   ├── udp.py              # UDP scanning
│   ├── banner.py           # Banner grabbing
│   ├── version.py          # Version detection probes
│   ├── os_detect.py        # TTL-based OS fingerprinting
│   ├── fingerprinting.py   # ADVANCED: Aggressive OS fingerprinting
│   ├── discovery.py        # ARP-based host discovery
│   ├── scripts.py          # NSE-style scripting engine
│   ├── lua_scripts.py      # ADVANCED: Nmap-style Lua scripts
│   ├── plugin_manager.py   # Dynamic plugin loader
│   ├── reporter.py         # JSON report generation
│   ├── proxy.py            # ADVANCED: Proxy routing support
│   ├── cve_engine.py       # ADVANCED: CVE database integration
│   ├── timing.py           # ADVANCED: Timing templates
│   ├── utils.py            # Port parsing utilities
│   └── interactive.py      # Interactive menu mode
│
├── plugins/
│   ├── http_plugin.py      # HTTP service plugin
│   └── ssh_plugin.py       # SSH service plugin
│
├── scripts/                # Custom Lua-style scripts directory
│   └── (place custom .lua scripts here)
│
├── main.py                 # CLI entry point
├── requirements.txt        # Python dependencies
├── .env.example            # Environment configuration template
├── README.md               # This file
└── LICENSE
```

---

## Root Privileges

The following features require root/sudo:

- `-M syn` or `-sS` — SYN scanning
- `-O` / `--os` — OS detection via TTL analysis
- `-sU` / `--udp` — UDP scanning

**Why?** These features use raw socket access, which is restricted to root on Linux.

---

## Future Improvements

1. **Distributed Scanning** — Multi-machine agent support for large-scale network reconnaissance
2. **Web Dashboard** — Real-time scan visualization and results browser
3. **Advanced Machine Learning** — ML-based OS detection using network signatures
4. **Traceroute Visualization** — Network path mapping and topology visualization
5. **Brute-Force Modules** — Integrated credential testing (SSH, HTTP, FTP)
6. **Stealth Modes** — Packet fragmentation, IP spoofing, randomized timing
7. **Service Behavior Analysis** — Deep protocol analysis and anomaly detection
8. **Custom Exploit Integration** — Automated vulnerability exploitation
9. **Docker Support** — Containerized SpectreScan deployment
10. **Cloud Provider Integration** — AWS/Azure/GCP asset scanning

---

## Technologies Used

- **Python 3** — Core language
- **Asyncio** — Asynchronous I/O for concurrent scanning
- **Scapy** — Raw packet crafting
- **Rich** — Beautiful terminal UI
- **Socket** — Network operations

---

## Legal Disclaimer

This project is intended strictly for:

- Educational purposes
- Authorized security testing
- Personal lab environments
- CTF platforms (HackTheBox, TryHackMe)

**Do not scan systems or networks without explicit authorization.**

---

## Author

Deepanshu  
Enhanced with interactive UI, advanced OS detection, and Nmap-style features.

