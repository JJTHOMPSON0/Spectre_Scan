# Spectre_Scan
# SpectreScan

SpectreScan is a modular Nmap-inspired network reconnaissance framework built in Python.

## Features

- Async network scanning
- CIDR subnet scanning
- SYN scanning using Scapy
- Banner grabbing
- Plugin architecture
- Optional JSON report generation
- Lightweight and modular

## Installation

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

### Scan Single Host

```bash
python main.py 127.0.0.1
```

### Scan Entire Subnet

```bash
python main.py 192.168.1.0/24
```

### SYN Scan

```bash
sudo python main.py 192.168.1.0/24 --syn
```

### Custom Port Range

```bash
python main.py 192.168.1.0/24 --start 1 --end 5000
```

### Save Report

```bash
python main.py 192.168.1.0/24 --save report.json
```

## Legal Disclaimer

Use only on systems you own or are authorized to test.
>>>>>>> 5be9ed6 (Initial commit: Added core scanning engine and plugins)
