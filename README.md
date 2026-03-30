# ATOMIC FRAMEWORK v7.0 - ULTIMATE EDITION

⚠️ **FOR AUTHORIZED TESTING ONLY** ⚠️

A powerful, modular web security testing framework optimized for Termux (Android) and Linux systems.

## Features

### Attack Modules
- **SQL Injection** - Error-based, Union-based, Time-based, Boolean-based
- **NoSQL Injection** - MongoDB, CouchDB injection tests
- **Command Injection** - RCE detection and exploitation
- **XSS** - Reflected, Stored, DOM-based
- **LFI/RFI** - Local/Remote File Inclusion
- **SSRF** - Server-Side Request Forgery
- **SSTI** - Server-Side Template Injection
- **XXE** - XML External Entity
- **IDOR** - Insecure Direct Object Reference
- **CORS** - CORS Misconfiguration
- **JWT** - JWT Security Weaknesses
- **File Upload** - Upload bypass tests

### Advanced Features
- **Shell Upload** - Automatic web shell deployment
- **Data Dumper** - Database extraction and file dumping
- **WAF Bypass** - Multiple evasion techniques
- **Reconnaissance** - Subdomain enumeration, technology detection
- **Report Generation** - HTML, JSON, CSV, PDF, TXT

### Evasion & Stealth
- Multiple evasion levels (none, low, medium, high, insane, stealth)
- WAF bypass techniques
- User-Agent rotation
- Proxy support (including Tor)
- Request delay control

## Installation

### Termux
```bash
# Update packages
pkg update && pkg upgrade -y

# Install dependencies
pkg install python clang libffi openssl git -y

# Clone/download framework
cd atomic_framework

# Run setup
bash setup.sh
```

### Linux
```bash
# Install dependencies
sudo apt-get update
sudo apt-get install python3 python3-pip python3-dev clang libffi-dev openssl git -y

# Install Python packages
pip3 install -r requirements.txt

# Run setup
bash setup.sh
```

## Usage

### Basic Scan
```bash
python main.py -t https://target.com
```

### Full Scan (All Modules)
```bash
python main.py -t https://target.com --full
```

### Deep Scan with Shell Upload
```bash
python main.py -t https://target.com -d 5 --shell --dump
```

### With WAF Bypass
```bash
python main.py -t https://target.com --full --waf-bypass --evasion high
```

### List Previous Scans
```bash
python main.py --list-scans
```

### Generate Report
```bash
python main.py --report <scan_id> --format html
```

### Interactive Shell Manager
```bash
python main.py --shell-manager
```

## Command Line Options

### Target Options
- `-t, --target` - Target URL
- `-f, --file` - File with list of targets
- `--urls` - Comma-separated URLs

### Scan Options
- `-d, --depth` - Crawl depth (default: 3)
- `-T, --threads` - Number of threads (default: 50)
- `--timeout` - Request timeout (default: 15)
- `--delay` - Delay between requests (default: 0.1)

### Module Options
- `--full` - Enable all modules
- `--sqli` - SQL Injection
- `--xss` - XSS
- `--lfi` - LFI/RFI
- `--cmdi` - Command Injection
- `--ssrf` - SSRF
- `--ssti` - SSTI
- `--xxe` - XXE
- `--idor` - IDOR
- `--nosql` - NoSQL Injection
- `--cors` - CORS
- `--jwt` - JWT

### Exploitation Options
- `--shell` - Attempt shell upload
- `--dump` - Attempt data dump
- `--os-shell` - Get OS shell
- `--brute` - Enable brute force

### Evasion Options
- `-e, --evasion` - Evasion level (none, low, medium, high, insane, stealth)
- `--waf-bypass` - Enable WAF bypass
- `--tor` - Route through Tor
- `--proxy` - Use proxy
- `--rotate-proxy` - Rotate proxies
- `--rotate-ua` - Rotate User-Agent

### Report Options
- `--report` - Generate report for scan ID
- `--format` - Report format (json, csv, html, pdf, txt, all)
- `--list-scans` - List all scans
- `-o, --output` - Output directory

## Project Structure

```
atomic_framework/
├── main.py                 # Entry point
├── config.py               # Configuration & payloads
├── requirements.txt        # Python dependencies
├── setup.sh               # Setup script
├── README.md              # This file
│
├── core/                  # Core modules
│   ├── engine.py          # Main attack engine
│   ├── banner.py          # Banner & UI
│   └── reporter.py        # Report generator
│
├── modules/               # Attack modules
│   ├── exploits/          # Exploit modules
│   │   ├── sqli.py       # SQL Injection
│   │   ├── xss.py        # XSS
│   │   ├── lfi.py        # LFI/RFI
│   │   ├── cmdi.py       # Command Injection
│   │   ├── ssrf.py       # SSRF
│   │   ├── ssti.py       # SSTI
│   │   ├── xxe.py        # XXE
│   │   ├── idor.py       # IDOR
│   │   ├── nosqli.py     # NoSQL Injection
│   │   ├── cors.py       # CORS
│   │   └── jwt.py        # JWT
│   │
│   ├── bypass/            # Bypass modules
│   │   └── waf.py        # WAF bypass
│   │
│   ├── dump/              # Data dump modules
│   │   └── dumper.py     # Data extraction
│   │
│   ├── shell/             # Shell modules
│   │   ├── uploader.py   # Shell upload
│   │   └── manager.py    # Shell management
│   │
│   └── recon/             # Recon modules
│       ├── crawler.py    # Web crawler
│       └── reconnaissance.py
│
├── utils/                 # Utilities
│   ├── database.py       # Database operations
│   ├── requester.py      # HTTP request handler
│   └── helpers.py        # Helper functions
│
├── reports/              # Generated reports
└── shells/               # Shell files
```

## Examples

### Scan with Specific Modules
```bash
python main.py -t https://target.com --sqli --xss --lfi
```

### Stealth Scan
```bash
python main.py -t https://target.com --full --evasion stealth -T 10 --delay 2
```

### Through Tor
```bash
python main.py -t https://target.com --full --tor
```

### With Proxy
```bash
python main.py -t https://target.com --full --proxy http://127.0.0.1:8080
```

## Safety & Legal Notice

This tool is intended for authorized security testing only. Always:
- Obtain proper authorization before testing
- Test only systems you own or have written permission to test
- Follow responsible disclosure practices
- Comply with all applicable laws and regulations

**The authors are not responsible for any misuse or damage caused by this tool.**

## License

This project is for educational purposes only.

## Credits

ATOMIC Framework v7.0 - ULTIMATE EDITION
Codename: PHOENIX
Optimized for Termux
