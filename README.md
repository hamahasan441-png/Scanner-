# ATOMIC FRAMEWORK v8.0 - ULTIMATE EDITION

⚠️ **FOR AUTHORIZED TESTING ONLY** ⚠️

A powerful, modular web security testing framework optimized for Termux (Android) and Linux systems. Features a Flask web dashboard, advanced evasion engine, and comprehensive vulnerability scanning.

## Quick Install

```bash
pip install -r requirements.txt
```

## Quick Start

```bash
# Launch web dashboard
python main.py --web

# Basic CLI scan
python main.py -t https://target.com

# Full scan with all modules
python main.py -t https://target.com --full

# Maximum evasion mode
python main.py -t https://target.com --full --evasion insane --waf-bypass
```

## Features

### 🚀 Flask Web Dashboard
- **Real-time scanning** with live status updates
- **Dark-themed UI** with severity-coded findings
- **Scan management** — start, monitor, delete scans from browser
- **Report downloads** — HTML, JSON, CSV, TXT
- **Dashboard statistics** — severity breakdown, scan history
- Launch: `python main.py --web`

### ⚔️ Attack Modules (12)
- **SQL Injection** — Error-based, Union-based, Time-based, Boolean-based, Stacked queries
- **NoSQL Injection** — MongoDB, CouchDB injection tests
- **Command Injection** — RCE detection and exploitation
- **XSS** — Reflected, Stored, DOM-based, Polyglot payloads
- **LFI/RFI** — Local/Remote File Inclusion
- **SSRF** — Server-Side Request Forgery with cloud metadata extraction
- **SSTI** — Server-Side Template Injection (9 template engines)
- **XXE** — XML External Entity
- **IDOR** — Insecure Direct Object Reference
- **CORS** — CORS Misconfiguration
- **JWT** — JWT Security Weaknesses
- **File Upload** — Upload bypass tests (20+ extension variants)

### 🛡️ Advanced Evasion Engine
- **6 evasion levels**: none, low, medium, high, insane, stealth
- **Polymorphic payload mutation** — encoding chains, case alternation, comment injection, whitespace randomization, null bytes, CHAR() splitting, string concatenation, JS obfuscation, HTML entities, mixed encoding
- **HTTP fingerprint spoofing** — 9 browser profiles with matching Sec-CH-UA headers, randomized Accept/Language/Encoding
- **Anti-detection timing** — Gaussian-distributed delays, burst/pause patterns, exponential backoff on rate limiting
- **WAF bypass** — 13+ WAF detection signatures, chunked transfer encoding, HTTP method override, header spoofing

### 🔧 Advanced Features
- **Shell Upload** — Automatic web shell deployment
- **Data Dumper** — Database extraction and file dumping
- **WAF Detection & Bypass** — Cloudflare, AWS WAF, ModSecurity, Sucuri, Akamai, and more
- **Reconnaissance** — Subdomain enumeration, technology detection, DNS lookup
- **Advanced Crawler** — Hidden parameter discovery, JS variable extraction, API endpoint detection
- **Report Generation** — HTML, JSON, CSV, TXT
- **Scan Persistence** — SQLite database for scan history and findings
- **MITRE ATT&CK Mapping** — All findings mapped to MITRE techniques and CWE IDs

### 🕵️ Additional Payload Categories
- CRLF Injection
- HTTP Parameter Pollution
- Prototype Pollution
- GraphQL Injection
- Cloud Metadata Extraction (AWS, GCP, Azure, DigitalOcean)

## Installation

### Quick (Python only)
```bash
pip install -r requirements.txt
python main.py --web
```

### Termux
```bash
pkg update && pkg upgrade -y
pkg install python clang libffi openssl git -y
pip install -r requirements.txt
```

> **Note:** On Termux, packages like `lxml`, `cryptography`, and `paramiko` are excluded from `requirements.txt` because building their C extensions can hang or take very long. They are not required for core functionality. If you need them, install separately:
> ```bash
> pip install lxml cryptography paramiko
> ```

### Linux
```bash
sudo apt-get install python3 python3-pip -y
pip3 install -r requirements.txt
```

### Full Setup Script
```bash
bash setup.sh
```

## Usage

### Web Dashboard
```bash
python main.py --web                          # Launch on 0.0.0.0:5000
python main.py --web --web-port 8080          # Custom port
python main.py --web --web-host 127.0.0.1     # Localhost only
```

### CLI Scanning
```bash
python main.py -t https://target.com                          # Basic scan
python main.py -t https://target.com --full                   # All modules
python main.py -t https://target.com -d 5 -T 100             # Deep scan
python main.py -t https://target.com --sqli --xss --lfi      # Specific modules
python main.py -t https://target.com --shell --dump           # Exploitation
python main.py -t https://target.com --evasion insane         # Max evasion
python main.py -t https://target.com --full --waf-bypass      # WAF bypass
python main.py -t https://target.com --full --tor             # Through Tor
python main.py -t https://target.com --evasion stealth -T 10  # Stealth mode
python main.py -f targets.txt --full                          # Batch scan
```

### Reports & History
```bash
python main.py --list-scans                    # List previous scans
python main.py --report <scan_id> --format html  # Generate report
python main.py --shell-manager                 # Manage active shells
```

## Command Line Options

| Category | Option | Description |
|----------|--------|-------------|
| **Target** | `-t, --target` | Target URL |
| | `-f, --file` | File with list of targets |
| | `--urls` | Comma-separated URLs |
| **Scan** | `-d, --depth` | Crawl depth (default: 3) |
| | `-T, --threads` | Number of threads (default: 50) |
| | `--timeout` | Request timeout (default: 15) |
| | `--delay` | Delay between requests (default: 0.1) |
| **Modules** | `--full` | Enable all modules |
| | `--sqli, --xss, --lfi, --cmdi` | Individual modules |
| | `--ssrf, --ssti, --xxe, --idor` | Individual modules |
| | `--nosql, --cors, --jwt, --upload` | Individual modules |
| **Exploit** | `--shell` | Attempt shell upload |
| | `--dump` | Attempt data dump |
| | `--os-shell` | Get OS shell |
| **Evasion** | `-e, --evasion` | Level: none/low/medium/high/insane/stealth |
| | `--waf-bypass` | Enable WAF bypass |
| | `--tor` | Route through Tor |
| | `--proxy` | Use HTTP proxy |
| | `--rotate-ua` | Rotate User-Agent |
| **Web** | `--web` | Launch Flask dashboard |
| | `--web-host` | Dashboard host (default: 0.0.0.0) |
| | `--web-port` | Dashboard port (default: 5000) |
| **Reports** | `--report` | Generate report for scan ID |
| | `--format` | Report format (json/csv/html/txt/all) |
| | `--list-scans` | List all scans |

## Project Structure

```
Scanner-/
├── main.py                  # CLI entry point
├── config.py                # Configuration, payloads, MITRE mapping
├── requirements.txt         # Python dependencies
├── setup.sh                 # Setup script
├── core/
│   ├── engine.py            # Scan orchestration engine
│   ├── reporter.py          # Multi-format report generation
│   └── banner.py            # ASCII banner
├── modules/
│   ├── sqli.py, xss.py, lfi.py, cmdi.py   # Attack modules
│   ├── ssrf.py, ssti.py, xxe.py, idor.py  # Attack modules
│   ├── nosqli.py, cors.py, jwt.py         # Attack modules
│   ├── uploader.py, dumper.py              # Exploitation
│   ├── waf.py                              # WAF detection & bypass
│   ├── reconnaissance.py                   # Recon module
│   └── shell/manager.py                    # Shell management
├── utils/
│   ├── requester.py         # Advanced HTTP client with evasion
│   ├── crawler.py           # Web crawler with hidden param discovery
│   ├── evasion.py           # Advanced evasion engine
│   ├── database.py          # SQLAlchemy ORM
│   └── helpers.py           # Utilities
├── web/
│   ├── app.py               # Flask web dashboard
│   ├── templates/index.html # Dashboard UI
│   └── static/style.css     # Dashboard styles
├── reports/                 # Generated reports
└── shells/                  # Shell files
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

ATOMIC Framework v8.0 - ULTIMATE EDITION
Codename: PHOENIX
