<p align="center">
  <img src="assets/banner.jpeg" width="950">
</p>

# SpectreScan

[![DOCS](https://img.shields.io/badge/DOCS-SpectreScan-blue?style=for-the-badge)](#readme) [![LICENSE](https://img.shields.io/badge/LICENSE-MIT-green?style=for-the-badge)](LICENSE) [![BUILT BY](https://img.shields.io/badge/BUILT%20BY-Deepanshu-purple?style=for-the-badge)](#) [![LANG](https://img.shields.io/badge/LANG-EN-lightgrey?style=for-the-badge)](#)

> A modular Nmap-inspired network reconnaissance framework in Python.

SpectreScan is built for security learning, authorized reconnaissance, and lab testing. It supports asynchronous scanning, SYN and UDP probes, OS fingerprinting, version detection, scripting, plugins, proxy routing, and optional CVE lookups.


## ✨ What SpectreScan Does

- Asynchronous TCP connect scanning
- TCP SYN scanning when running as root
- UDP scanning support
- CIDR/subnet discovery
- OS detection using TTL analysis
- Service and version probing
- Nmap-style scripting engine
- Plugin-based service detection
- Optional CVE lookups via NVD
- Proxy routing through HTTP/HTTPS/SOCKS5
- JSON report export

---

## 📦 Installation

1.Clone the repository:

```bash
git clone https://github.com/yourusername/SpectreScan.git
cd SpectreScan
```
2.Start a python virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

### Interactive Mode (Console)

Running SpectreScan without arguments or with the `-i` flag launches the interactive CLI shell:

```bash
python main.py
# or
python main.py -i
```

This starts a custom console shell (`spectre ❯ `) featuring a professional command interface with command auto-completion.

### 💻 Interactive Console Walkthrough

Here is a step-by-step example of how the interactive console functions in practice:

#### 1. Show & Adjust Configuration (`show options` / `set`)
Use the `show options` command to see the default configuration state, then use `set` to modify options dynamically:
```text
spectre ❯ show options

SpectreScan Current Configuration:
+---------------------------+------------+-------------------------------------------------------------+
| Option                    | Value      | Description                                                 |
+---------------------------+------------+-------------------------------------------------------------+
| target                    |            | Target IP address, hostname, or CIDR (e.g. 192.168.1.1/24)  |
| ports                     | 22,80,443  | Port range or list, e.g. 22,80,443,1000-2000                |
| scan_type                 | auto       | Scan type: auto, tcp, syn, udp, all                         |
| version_detect            | True       | Probe service versions (-sV)                                |
| os_detect                 | False      | Enable OS detection via TTL (requires root)                 |
| scripts                   | False      | Run built-in Nmap-style scripts (-sC)                       |
+---------------------------+------------+-------------------------------------------------------------+

spectre ❯ set target 127.0.0.1
[+] Set target ❯ 127.0.0.1

spectre ❯ set ports 80,443
[+] Set ports ❯ 80,443

spectre ❯ set version_detect True
[+] Set version_detect ❯ True
```

#### 2. Run the Scan Engine (`scan`)
Type `scan` to trigger host discovery and the asynchronous scanning engine:
```text
spectre ❯ scan

[*] Initiating SpectreScan...
Target: 127.0.0.1
Ports: 80,443

[+] Running TCP connect scan on 1 host(s)...
[+] 127.0.0.1:80/tcp OPEN HTTP/1.1 200 OK (nginx/1.18.0)
[+] 127.0.0.1:443/tcp OPEN HTTP/1.1 200 OK (nginx/1.18.0)

[+] Checking for service CVEs...
[+] nginx 1.18.0 has 3 known CVEs

Scan Results:
+-----------+------------+--------+-----------------+-----+
| HOST      | PORT       | STATE  | SERVICE/VERSION | OS  |
+-----------+------------+--------+-----------------+-----+
| 127.0.0.1 | 80/tcp     | open   | nginx 1.18.0    | -   |
| 127.0.0.1 | 443/tcp    | open   | nginx 1.18.0    | -   |
+-----------+------------+--------+-----------------+-----+
[+] Scan completed in 0.45 seconds. Loaded results in memory.
#### 3. Interactively Check Service Vulnerabilities (`cvecheck`)
You can manually check specific service banners for known CVEs:
```text
spectre ❯ cvecheck apache 2.4.41

[*] Fetching CVEs for service: apache (Version: 2.4.41)...

CVEs for apache:
+----------------+----------------------------------------------------+--------+
| CVE ID         | Description                                        | Score  |
+----------------+----------------------------------------------------+--------+
| CVE-2020-1927  | Apache HTTP Server versions 2.4.0 to 2.4.41...     | HIGH   |
| CVE-2020-1934  | Apache HTTP Server versions 2.4.0 to 2.4.41...     | MEDIUM |
| CVE-2021-26691 | Apache HTTP Server versions 2.4.0 to 2.4.46...     | HIGH   |
+----------------+----------------------------------------------------+--------+
```

#### 4. View Script Library & Plugins (`show scripts` / `show plugins`)
Inspect active script suites and detection extensions:
```text
spectre ❯ show scripts

Nmap-Style Script Library:
+-------------------+------------+------------------------------------+
| Name              | Category   | Description                        |
+-------------------+------------+------------------------------------+
| ssl-cert          | ssl        | Extracts SSL certificate info      |
| http-enum         | http       | Enumerate common HTTP paths        |
| smb-os-discovery  | smb        | Enumerate SMB OS information       |
+-------------------+------------+------------------------------------+
```

---

### Command-line Mode

If you supply a target argument, SpectreScan executes immediately in standard command-line mode:

```bash
python main.py 192.168.1.1
python main.py 192.168.1.1 -P 22,80,443
sudo python main.py 192.168.1.1 -M syn -O -sV
python main.py 192.168.1.1 -sU -P 53,123,161
python main.py 192.168.1.1 -sV --check-cve
python main.py 192.168.1.1 --proxy socks5://127.0.0.1:1080
python main.py 192.168.1.1 -sC -p -o scan_report.json
```

---

## 🧭 Command-line Options

```bash
python main.py -h
```

The available CLI options are:

- `-h, --help` — show help message and exit
- `-i, --interactive` — launch interactive menu mode
- `-P, --ports PORTS` — port range or list, e.g. `22,80,443,1000-2000`
- `-M, --scan-type {auto,tcp,syn,udp,all}` — scan type to perform
- `-T, --timing-template {0,1,2,3,4,5}` — timing template
- `--timeout TIMEOUT` — connection timeout in seconds
- `-c, --concurrency CONCURRENCY` — maximum concurrent probes
- `-n, --no-discovery` — skip host discovery
- `-sS, --syn` — perform TCP SYN scan (requires root)
- `-sU, --udp` — perform UDP scan
- `-O, --os` — enable OS detection via TTL
- `--aggressive-fingerprinting` — enable advanced OS fingerprinting
- `-sV, --version` — probe open ports for service/version info
- `--check-cve` — check detected services for known CVEs
- `-sC, --scripts` — run built-in Nmap-style scripts
- `-C, --script-categories SCRIPT_CATEGORIES` — comma-separated script categories
- `-p, --plugins` — run service plugins from the `plugins/` folder
- `--proxy PROXY_URL` — use proxy (e.g. `http://host:port`, `socks5://host:port`)
- `-o, --save FILE` — save JSON report to file

### Scan type notes

- `auto` — SYN scan if running as root, otherwise TCP connect scan
- `tcp` — TCP connect scan only
- `syn` — TCP SYN scan (root required)
- `udp` — UDP scan only
- `all` — TCP + SYN + UDP (SYN and OS detection may be disabled if not root)

---

## ⚙️ Configuration

SpectreScan loads environment variables from a `.env` file using `python-dotenv`. Copy `.env.example` to `.env`, then fill in values.

```bash
cp .env.example .env
```

### Environment variables

```bash
# Proxy Settings
PROXY_HTTP=
PROXY_HTTPS=
PROXY_SOCKS5=

# CVE Database
CVE_API_KEY=
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

### What these variables do

- `PROXY_HTTP`, `PROXY_HTTPS`, `PROXY_SOCKS5` — proxy routing for outbound scan traffic
- `CVE_API_KEY` — NVD API key used by `--check-cve`
- `NVD_API_URL` — NVD endpoint for CVE lookups
- `SHODAN_API_KEY`, `CENSYS_API_KEY` — placeholders for future service detection integrations
- `DEFAULT_SCAN_TYPE`, `DEFAULT_TIMEOUT`, `DEFAULT_CONCURRENCY` — fallback scan defaults
- `LOG_LEVEL`, `LOG_FILE` — logging configuration

---

## 🧠 Timing Templates

Use `-T` to choose a scan speed profile:

- `0` — Paranoid: very slow, stealthy
- `1` — Sneaky: quiet and cautious
- `2` — Polite: reduced network load
- `3` — Normal: balanced speed/stealth (default)
- `4` — Aggressive: fast scanning
- `5` — Insane: maximum speed

Example:

```bash
python main.py 192.168.1.1 -T3
```

---

## 🛡️ CVE Integration

Enable CVE checking with:

```bash
python main.py 192.168.1.1 -sV --check-cve
```

This will query the NVD API for known vulnerabilities related to detected service/version strings.

### Setup

1. Register for an NVD API key at:
   `https://nvd.nist.gov/developers/request-an-api-key`
2. Add the key to `.env`:
   `CVE_API_KEY=your_key_here`

---

## 🌐 Proxy Routing

Use a proxy for scan traffic:

```bash
python main.py 192.168.1.1 --proxy socks5://127.0.0.1:1080
```

Or configure proxies via environment variables.

---

## 🧩 Plugins & Scripts

### Plugins

Plugins live in `plugins/` and are loaded when `-p` is enabled.

Example plugin usage:

```bash
python main.py 192.168.1.1 -p
```

### Scripts

Enable built-in scripts with `-sC`.

```bash
python main.py 192.168.1.1 -sC
```

Use `-C` to choose categories like `default`, `http`, or `ssh`.

---

## 🧪 Help and Validation

The tool supports two help methods:

- `python main.py -h`
- `python main.py help`

If a target is missing or invalid, the scanner will print an error and stop.

---

## 📁 Project Layout

```
SpectreScan/
├── core/                 # scanner internals and modules
├── plugins/              # service plugins
├── scripts/              # optional Lua-style scripts
├── main.py               # CLI entry point
├── requirements.txt      # Python dependencies
├── .env.example          # config template
└── README.md             # documentation
```


---

## ⚖️ Disclaimer

Use SpectreScan only on systems you own or are authorized to test. Unauthorized scanning is illegal.
