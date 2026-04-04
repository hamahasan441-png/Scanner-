# ATOMIC FRAMEWORK v8.2 — ULTIMATE EDITION

⚠️ **FOR AUTHORIZED TESTING ONLY** ⚠️

A powerful, modular web security testing framework optimized for Termux (Android) and Linux systems. Features an AI-powered vulnerability prediction engine, Burp Suite-style tools, exploit chaining, a Flask web dashboard, advanced evasion engine, and comprehensive vulnerability scanning across 27+ attack modules.

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

# AI-driven post-exploitation
python main.py -t https://target.com --full --auto-exploit

# Maximum evasion mode with WAF bypass
python main.py -t https://target.com --full --evasion insane --waf-bypass
```

## Features

### 🚀 Flask Web Dashboard
- **Real-time scanning** with live WebSocket status updates (SocketIO with polling fallback)
- **Dark-themed UI** with severity-coded findings
- **Scan management** — start, monitor, cancel, delete scans from browser
- **Report downloads** — HTML, JSON, CSV, TXT, PDF, XML, SARIF
- **Dashboard statistics** — severity breakdown, scan history
- **API endpoints** with optional API key authentication and rate limiting
- **File/batch scan** — Single target or multi-target file upload
- Launch: `python main.py --web`

### ⚔️ Attack Modules (27+)
- **SQL Injection** — Error-based, Union-based, Time-based, Boolean-based, Stacked queries
- **NoSQL Injection** — MongoDB operator injection, CouchDB, JavaScript evaluation
- **Command Injection** — RCE detection and exploitation, reverse shell generation
- **XSS** — Reflected, Stored, DOM-based, Polyglot payloads (20+ variants)
- **LFI/RFI** — Local/Remote File Inclusion with wrapper protocols (php://, file://, data://)
- **SSRF** — Server-Side Request Forgery with cloud metadata extraction (AWS, GCP, Azure, DigitalOcean)
- **SSTI** — Server-Side Template Injection (9 engines: Jinja2, Mako, Django, Twig, Velocity, Thymeleaf, FreeMarker, EL, Groovy)
- **XXE** — XML External Entity injection, file disclosure, SSRF via XXE
- **IDOR** — Insecure Direct Object Reference with authorization bypass
- **CORS** — CORS Misconfiguration detection
- **JWT** — Algorithm confusion, signature bypass, claim manipulation
- **File Upload** — Upload bypass tests (20+ extension variants, magic bytes, polyglots)
- **CRLF Injection** — Header injection detection
- **HTTP Parameter Pollution** — HPP across multiple frameworks
- **Open Redirect** — URL redirect detection
- **GraphQL Injection** — Schema introspection, query injection, mutation abuse
- **Prototype Pollution** — `__proto__` and constructor.prototype pollution
- **Port Scanner** — TCP port scanning with service detection
- **Network Exploit Mapping** — CVE mapping for open ports/services
- **Technology Exploit Mapping** — CVE mapping for detected technologies
- **WAF Detection & Bypass** — 13+ WAF signatures (Cloudflare, AWS WAF, ModSecurity, Sucuri, Akamai, Imperva, etc.)
- **Brute Force** — Credential brute forcing
- **Data Dumper** — Database extraction and file dumping
- **Shell Uploader** — Automatic web shell deployment
- **Discovery** — robots.txt, sitemap, API endpoint discovery
- **Reconnaissance** — Subdomain enumeration, technology detection, DNS lookup

### 🧠 AI-Powered Vulnerability Engine
- **ML-based vulnerability prediction** — Feature extraction from URLs, parameters, and responses
- **Smart payload selection** — Highest-scoring payloads tested first
- **Anomaly detection** — Baseline response analysis with statistical methods
- **Adaptive testing strategy** — Per-URL strategy generation based on context
- **Confidence calibration** — Calibrated probability adjustments
- **Vulnerability correlation** — Identifies related vulnerability patterns
- **Exploit difficulty estimation** — Rates exploitation complexity
- **Tech-aware payloads** — Payload hints based on detected technology stack
- **WAF evasion profiles** — Adaptive evasion based on detected WAF

### 🔗 Exploit Chaining & Post-Exploitation
- **Multi-step exploit chains** — SSRF → SQLi → Dump, File Upload → RCE → Post-Exploit, LFI → Source Disclosure
- **AI-driven post-exploitation** — Automatic exploitation prioritization via `--auto-exploit`
- **Shell management** — Track uploaded shells, active enumeration, command logging
- **OS shell interaction** — Interactive command execution via discovered vulnerabilities
- **Persistence tracking** — Track exploitation state across scan sessions

### 🛡️ Advanced Evasion Engine
- **6 evasion levels**: none, low, medium, high, insane, stealth
- **Polymorphic payload mutation** — encoding chains, case alternation, comment injection, whitespace randomization, null bytes, CHAR() splitting, string concatenation, JS obfuscation, HTML entities, mixed encoding
- **HTTP fingerprint spoofing** — 9 browser profiles with matching Sec-CH-UA headers, randomized Accept/Language/Encoding
- **Anti-detection timing** — Gaussian-distributed delays, burst/pause patterns, exponential backoff on rate limiting
- **WAF bypass** — chunked transfer encoding, HTTP method override, header spoofing

### 🔧 Burp Suite-Style Tools
- **Intercepting Proxy** — Man-in-the-middle proxy with request/response modification (`--proxy-server`)
- **Repeater** — Replay and modify raw HTTP requests (`--repeater`)
- **Intruder** — Automated payload injection with 4 attack types: sniper, battering ram, pitchfork, cluster bomb (`--intruder`)
- **Decoder** — Smart multi-format encoding/decoding: Base64, URL, HTML, Hex, and more (`--decode` / `--encode`)
- **Sequencer** — Token randomness and entropy analysis (`--sequencer`)
- **Comparer** — HTTP response diffing and similarity analysis (`--compare`)

### 📊 Reporting & Intelligence
- **Multi-format reports** — HTML, JSON, CSV, TXT, PDF, XML, SARIF
- **MITRE ATT&CK mapping** — All findings mapped to MITRE techniques
- **CWE identification** — Common Weakness Enumeration IDs
- **CVSS scoring** — Automated severity calculation
- **Remediation suggestions** — Actionable fix recommendations per finding
- **Scan persistence** — SQLite database for scan history and findings
- **SARIF output** — GitHub Code Scanning integration

### 🔍 Smart Scanning Pipeline
- **Adaptive testing** — Baseline establishment, parameter classification, context-aware testing
- **Endpoint prioritization** — Risk-based ordering of test targets
- **Signal scoring** — Multi-signal analysis (error, timing, status, reflection, diff)
- **Finding verification** — Automatic false positive elimination
- **Response normalization** — Removes dynamic content for accurate comparison
- **Scope enforcement** — Policy-based URL/domain filtering
- **Learning store** — Historical payload win/loss tracking

## Installation

### Prerequisites
- **Python 3.9** or higher
- **pip** (Python package manager)
- **Git** (for cloning)

### Quick (Python only)
```bash
git clone https://github.com/hamahasan441-png/Scanner-.git
cd Scanner-
pip install -r requirements.txt
python main.py --web
```

### Termux (Android)
```bash
pkg update && pkg upgrade -y
pkg install python clang libffi openssl git -y
git clone https://github.com/hamahasan441-png/Scanner-.git
cd Scanner-
pip install -r requirements.txt
```

> **Note:** On Termux, packages like `lxml`, `cryptography`, and `paramiko` are excluded from `requirements.txt` because building their C extensions can hang or take very long. They are not required for core functionality. If you need them, install separately:
> ```bash
> pip install lxml cryptography paramiko
> ```

### Linux (Debian/Ubuntu)
```bash
sudo apt-get update
sudo apt-get install python3 python3-pip python3-venv git -y
git clone https://github.com/hamahasan441-png/Scanner-.git
cd Scanner-
pip3 install -r requirements.txt
```

### Full Setup Script
```bash
git clone https://github.com/hamahasan441-png/Scanner-.git
cd Scanner-
bash setup.sh
```

### External Security Tools

The framework integrates with 20 external security tools for enhanced scanning capabilities. These are **optional** — the framework works without them, but enables additional features when they are installed.

```bash
# Check which tools are installed
python main.py --tools-check

# Install all missing tools automatically
python main.py --tools-install

# Install a specific tool
python main.py --tools-install --tool nuclei
```

**Supported tools:**

| Category | Tools | Install Method |
|----------|-------|---------------|
| Network Scanning | Nmap, Masscan, RustScan | apt/brew/cargo |
| Vulnerability Scanning | Nuclei, Nikto | go/apt/brew |
| Subdomain Enumeration | Amass, Subfinder, dnsx | go/apt/brew |
| HTTP Probing | httpx | go/brew |
| Web Crawling | Katana, Hakrawler | go/brew |
| URL Harvesting | gau, waybackurls, ParamSpider | go/pip |
| Parameter Discovery | Arjun | pip |
| Directory Brute Force | ffuf, Gobuster, Feroxbuster, Dirsearch | go/apt/cargo/pip |
| Reconnaissance | WhatWeb | apt/brew |

> **Prerequisites for Go tools:** Install Go 1.21+ from https://go.dev/dl/
> **Prerequisites for Rust tools:** Install Rust from https://rustup.rs/

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
python main.py -t https://target.com --regulated-mission --authorized   # Regulated mission workflow
python main.py -t https://target.com --regulated-mission --authorized --allow-domain example.com --allow-path /api --exclude-path /admin
python main.py -t https://target.com --full                   # All modules
python main.py -t https://target.com -d 5 -T 100             # Deep scan
python main.py -t https://target.com --sqli --xss --lfi      # Specific modules
python main.py -t https://target.com --shell --dump           # Exploitation
python main.py -t https://target.com --auto-exploit           # AI post-exploitation
python main.py -t https://target.com --exploit-chain          # Multi-step chains
python main.py -t https://target.com --evasion insane         # Max evasion
python main.py -t https://target.com --full --waf-bypass      # WAF bypass
python main.py -t https://target.com --full --tor             # Through Tor
python main.py -t https://target.com --evasion stealth -T 10  # Stealth mode
python main.py -f targets.txt --full                          # Batch scan
```

### Reconnaissance & Discovery
```bash
python main.py -t https://target.com --recon                  # Full reconnaissance
python main.py -t https://target.com --subdomains             # Subdomain enumeration
python main.py -t https://target.com --ports 80,443,8080      # Port scan
python main.py -t https://target.com --tech-detect            # Technology detection
python main.py -t https://target.com --dir-brute              # Directory brute force
python main.py -t https://target.com --discovery              # robots.txt, sitemap, API
python main.py -t https://target.com --net-exploit            # CVE mapping for ports
python main.py -t https://target.com --tech-exploit           # CVE mapping for tech
```

### Burp Suite-Style Tools
```bash
python main.py --proxy-server                                 # Start intercepting proxy
python main.py --proxy-server --proxy-intercept               # Proxy with intercept
python main.py --repeater < request.txt                       # Replay raw HTTP request
python main.py -t https://target.com?id=1 --intruder          # Intruder attack
python main.py --decode "dGVzdA=="                            # Smart decode data
python main.py --encode "test" --encode-type base64           # Encode data
python main.py --sequencer < tokens.txt                       # Token randomness analysis
python main.py --compare resp1.txt resp2.txt                  # Compare responses
```

### Reports & Shell Management
```bash
python main.py --list-scans                                   # List previous scans
python main.py --report <scan_id> --format html               # Generate report
python main.py --report <scan_id> --format sarif              # SARIF for GitHub
python main.py --report <scan_id> --format all                # All formats
python main.py --shell-manager                                # Manage active shells
python main.py --shell-id <id> --shell-cmd "whoami"           # Execute shell command
```

### Utilities
```bash
python main.py --check-deps                                   # Verify Python dependencies
python main.py --install-deps                                 # Install Python dependencies
python main.py --tools-check                                  # Check external tool availability
python main.py --tools-install                                # Download & install all missing tools
python main.py --tools-install --tool nmap                    # Install a specific tool
python main.py --clear-db                                     # Clear scan database
```

## Command Line Options

| Category | Option | Description |
|----------|--------|-------------|
| **Target** | `-t, --target` | Target URL |
| | `-f, --file` | File with list of targets |
| | `--urls` | Comma-separated URLs |
| | `--authorized` | Confirm authorization for regulated mission scans |
| | `--strict-scope` | Do not auto-expand scope from target host |
| | `--allow-domain` | Comma-separated allowed domains |
| | `--allow-path` | Comma-separated allowed path prefixes |
| | `--exclude-path` | Comma-separated excluded path prefixes |
| | `--regulated-mission` | Enforce regulated mission order defaults |
| **Scan** | `-d, --depth` | Crawl depth (1-10, default: 3) |
| | `-T, --threads` | Number of threads (default: 50) |
| | `--timeout` | Request timeout in seconds (default: 15) |
| | `--delay` | Delay between requests (default: 0.1) |
| **Modules** | `--full` | Enable all modules |
| | `--sqli` | SQL Injection |
| | `--xss` | Cross-Site Scripting |
| | `--lfi` | Local/Remote File Inclusion |
| | `--cmdi` | Command Injection |
| | `--ssrf` | Server-Side Request Forgery |
| | `--ssti` | Server-Side Template Injection |
| | `--xxe` | XML External Entity |
| | `--idor` | Insecure Direct Object Reference |
| | `--nosql` | NoSQL Injection |
| | `--cors` | CORS Misconfiguration |
| | `--jwt` | JWT Security |
| | `--upload` | File Upload Bypass |
| | `--open-redirect` | Open Redirect |
| | `--crlf` | CRLF Injection |
| | `--hpp` | HTTP Parameter Pollution |
| | `--graphql` | GraphQL Injection |
| | `--proto-pollution` | Prototype Pollution |
| **Exploit** | `--shell` | Attempt shell upload |
| | `--dump` | Attempt data dump |
| | `--os-shell` | Get OS shell |
| | `--brute` | Brute force attacks |
| | `--exploit-chain` | Multi-step exploit chaining |
| | `--auto-exploit` | AI-driven post-exploitation |
| **Evasion** | `-e, --evasion` | Level: none/low/medium/high/insane/stealth |
| | `--waf-bypass` | Enable WAF bypass |
| | `--tor` | Route through Tor |
| | `--proxy` | Use HTTP proxy |
| | `--rotate-proxy` | Rotate proxy addresses |
| | `--rotate-ua` | Rotate User-Agent |
| **Recon** | `--recon` | Full reconnaissance |
| | `--subdomains` | Subdomain enumeration |
| | `--ports` | Port scan (comma-separated) |
| | `--tech-detect` | Technology detection |
| | `--dir-brute` | Directory brute force |
| | `--discovery` | robots.txt, sitemap, API discovery |
| | `--net-exploit` | Map open ports to known CVEs |
| | `--tech-exploit` | Map technologies to known CVEs |
| **Web** | `--web` | Launch Flask dashboard |
| | `--web-host` | Dashboard host (default: 0.0.0.0) |
| | `--web-port` | Dashboard port (default: 5000) |
| **Reports** | `--report` | Generate report for scan ID |
| | `--format` | Format: json/csv/html/txt/pdf/xml/sarif/all |
| | `--list-scans` | List all previous scans |
| | `-o, --output` | Output directory |
| **Burp Tools** | `--proxy-server` | Start intercepting proxy |
| | `--proxy-port` | Proxy listen port (default: 8080) |
| | `--proxy-intercept` | Enable intercept mode |
| | `--repeater` | Replay raw HTTP request from stdin |
| | `--intruder` | Intruder attack on target |
| | `--intruder-type` | Attack type: sniper/battering_ram/pitchfork/cluster_bomb |
| | `--intruder-payloads` | Payload file for intruder |
| | `--decode` | Smart decode data |
| | `--encode` | Encode data |
| | `--encode-type` | Encoding: url/base64/hex/html/unicode/all |
| | `--sequencer` | Token randomness analysis |
| | `--compare` | Compare two response files |
| **Shells** | `--shell-manager` | Interactive shell manager |
| | `--shell-id` | Target specific shell |
| | `--shell-cmd` | Execute command on shell |
| **Utility** | `--check-deps` | Verify Python dependencies |
| | `--install-deps` | Install Python dependencies |
| | `--tools-check` | Check availability of all 20 external security tools |
| | `--tools-install` | Download and install missing external tools |
| | `--tool` | Specific tool name for `--tools-install` |
| | `--clear-db` | Clear scan database |
| | `-v, --verbose` | Verbose output |
| | `-q, --quiet` | Quiet mode |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         ☢  ATOMIC FRAMEWORK                             │
│                            main.py (CLI)                                │
├──────────────┬──────────────┬─────────────────┬─────────────────────────┤
│   Web UI     │  Burp Tools  │   Core Engine   │   AI Engine             │
│  (Flask)     │  Proxy       │  (Orchestrator) │  (ML Prediction)        │
│  Dashboard   │  Repeater    │  Crawler        │  Adaptive Testing       │
│  REST API    │  Intruder    │  Requester      │  Learning Store         │
│  WebSocket   │  Decoder     │  Baseline       │  Confidence Cal.        │
│  Trend Chart │  Sequencer   │  Verifier       │  Exploit Strategy       │
│  Glass UI    │  Comparer    │  Scorer         │  WAF Evasion Profiles   │
├──────────────┴──────────────┴────────┬────────┴─────────────────────────┤
│              §1 Setup                │       §2 Discovery               │
│  • Scope enforcement                 │  • Crawling & param extraction   │
│  • WAF detection & fingerprinting    │  • Reconnaissance (SSL, headers) │
│  • Baseline establishment            │  • Port scanning (TCP + UDP)     │
│  • Context intelligence              │  • Tech/CVE mapping              │
│  • Endpoint prioritization           │  • OSINT & Subdomain discovery   │
│  • Cloud/K8s asset detection         │  • Fuzzing (param, header, vhost)│
├──────────────────────────────────────┼──────────────────────────────────┤
│       §3 Vulnerability Scan          │     §4 Post-Exploitation         │
│  • 30+ attack modules (20 types)     │  • Shell upload (SVG, ZIP, MVG)  │
│  • SQLi: 2nd-order, OOB, WAF bypass  │  • Data dumping (DB extraction)  │
│  • XSS: mXSS, blind, CSP bypass     │  • OS shell (reverse/bind)       │
│  • SSRF: DNS rebind, K8s, PDF gen    │  • Brute force (auth, dirs)      │
│  • SSTI: sandbox escape, blind       │  • Exploit chaining              │
│  • JWT: JKU/X5U, kid, token replay   │  • AI auto-exploit strategies    │
│  • NoSQL: timing, pipeline, Redis    │  • Race condition exploitation   │
│  • Race conditions, WebSocket, Deser │  • WebSocket hijacking           │
│  • Signal scoring & verification     │  • Deserialization gadget chains │
│  • False positive elimination        │                                  │
├──────────────────────────────────────┴──────────────────────────────────┤
│                         §5 Reporting                                    │
│  HTML │ JSON │ CSV │ TXT │ PDF │ XML │ SARIF (GitHub Code Scanning)     │
│  MITRE ATT&CK │ CWE │ CVSS │ Remediation │ AI Confidence Scores        │
└─────────────────────────────────────────────────────────────────────────┘
```

### Scan Pipeline Flow

```
Target URL
    │
    ▼
┌─────────┐     ┌──────────┐     ┌──────────────┐     ┌─────────────┐
│  Scope  │────▶│  Recon   │────▶│  Crawl &     │────▶│ Vulnerability│
│  Check  │     │  OSINT   │     │  Parameter   │     │ Scanning     │
│  WAF    │     │  Ports   │     │  Discovery   │     │ (30+ modules)│
└─────────┘     └──────────┘     └──────────────┘     └──────┬──────┘
                                                              │
    ┌─────────────────────────────────────────────────────────┘
    │
    ▼
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  AI Engine   │────▶│  Post-       │────▶│  Report      │
│  Correlation │     │  Exploitation│     │  Generation  │
│  Scoring     │     │  Chaining    │     │  7 formats   │
└──────────────┘     └──────────────┘     └──────────────┘
```

## Project Structure

```
Scanner-/
├── main.py                      # CLI entry point
├── config.py                    # Configuration, payloads, MITRE ATT&CK mapping
├── requirements.txt             # Python dependencies (pinned versions)
├── pyproject.toml               # Package configuration
├── setup.sh                     # Setup script
│
├── core/                        # Core engine components (21 modules)
│   ├── engine.py                # Scan orchestration engine & Finding dataclass
│   ├── ai_engine.py             # ML-based vulnerability prediction & adaptive strategies
│   ├── reporter.py              # Multi-format report generation (HTML/JSON/CSV/TXT/PDF/XML/SARIF)
│   ├── adaptive.py              # Adaptive testing controller
│   ├── baseline.py              # Response baseline establishment & normalization
│   ├── context.py               # Context intelligence gathering
│   ├── prioritizer.py           # Risk-based endpoint prioritization
│   ├── scorer.py                # Signal scoring system
│   ├── verifier.py              # Finding verification & false positive elimination
│   ├── normalizer.py            # Response normalization
│   ├── learning.py              # Historical learning store for AI
│   ├── scope.py                 # Scope policy enforcement
│   ├── exploit_chain.py         # Multi-step exploitation chaining
│   ├── post_exploit.py          # AI-driven post-exploitation
│   ├── persistence.py           # Shell tracking & exploitation persistence
│   ├── os_shell.py              # OS shell interaction
│   ├── proxy.py                 # Intercepting proxy server (Burp-style)
│   ├── repeater.py              # Request repeater (Burp-style)
│   ├── intruder.py              # Intruder attack orchestration (Burp-style)
│   └── banner.py                # ASCII banner display
│
├── modules/                     # Attack & scan modules (30+)
│   ├── base.py                  # Abstract BaseModule interface
│   ├── sqli.py                  # SQL Injection (8 techniques: error, blind, union, 2nd-order, OOB, WAF bypass)
│   ├── xss.py                   # Cross-Site Scripting (reflected, stored, DOM, mXSS, blind, CSP bypass, polyglot)
│   ├── lfi.py                   # Local/Remote File Inclusion (PHP filters, Windows paths, log poisoning → RCE)
│   ├── cmdi.py                  # Command Injection (basic, blind, OOB, argument injection, env injection)
│   ├── ssrf.py                  # SSRF (internal, cloud, DNS rebinding, PDF gen, Kubernetes metadata)
│   ├── ssti.py                  # SSTI (12 engines, sandbox escape, blind/timing)
│   ├── xxe.py                   # XML External Entity
│   ├── nosqli.py                # NoSQL Injection (operators, JSON, JS, blind timing, aggregation, Redis)
│   ├── idor.py                  # Insecure Direct Object Reference
│   ├── cors.py                  # CORS Misconfiguration
│   ├── jwt.py                   # JWT (none alg, confusion, JKU/X5U, kid injection, token replay)
│   ├── crlf.py                  # CRLF Injection
│   ├── hpp.py                   # HTTP Parameter Pollution
│   ├── open_redirect.py         # Open Redirect Detection
│   ├── graphql.py               # GraphQL Injection (introspection, query, mutation)
│   ├── proto_pollution.py       # Prototype Pollution (__proto__, constructor)
│   ├── race_condition.py        # Race Condition (TOCTOU, parallel request timing)
│   ├── websocket.py             # WebSocket Injection (message injection, hijacking)
│   ├── deserialization.py       # Deserialization (Java, PHP, Python, Ruby, .NET gadget chains)
│   ├── uploader.py              # File Upload (20+ variants, SVG XSS, ImageTragick, ZIP symlink)
│   ├── dumper.py                # Data extraction / database dumping
│   ├── waf.py                   # WAF detection & bypass (13+ WAFs)
│   ├── brute_force.py           # Brute force attacks
│   ├── reconnaissance.py        # Subdomain, tech detect, SSL/TLS, security headers, cloud assets
│   ├── discovery.py             # robots.txt, sitemap, API discovery
│   ├── port_scanner.py          # TCP + UDP port scanning with service fingerprinting
│   ├── network_exploits.py      # CVE mapping for open ports/services
│   ├── tech_exploits.py         # CVE mapping for detected technologies
│   ├── osint.py                 # OSINT (Google dorking, GitHub leaks, Wayback Machine)
│   ├── fuzzer.py                # Fuzzing (parameter, header, method, vhost fuzzing)
│   └── shell/manager.py         # Web shell management
│
├── utils/                       # Utility modules (9)
│   ├── requester.py             # Advanced HTTP client with evasion & retries
│   ├── crawler.py               # Web crawler with hidden param discovery
│   ├── evasion.py               # Polymorphic evasion engine
│   ├── database.py              # SQLAlchemy ORM (ScanModel, FindingModel)
│   ├── decoder.py               # Smart encoding/decoding (Burp-style)
│   ├── sequencer.py             # Token randomness analysis (Burp-style)
│   ├── comparer.py              # Response diffing & similarity (Burp-style)
│   └── helpers.py               # Utility functions
│
├── web/                         # Flask web dashboard
│   ├── app.py                   # Flask application + REST API
│   ├── templates/index.html     # Dark-themed dashboard UI
│   └── static/style.css         # Dashboard styles
│
├── tests/                       # Test suite (57+ files, 1900+ tests)
│   ├── conftest.py              # Pytest configuration
│   └── test_*.py                # Unit & integration tests for all modules
│
└── .github/workflows/           # CI/CD pipelines
    ├── ci.yml                   # Lint, validate, test (Python 3.9-3.12)
    └── security.yml             # Bandit, CodeQL, pip-audit scans
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing, and contribution guidelines.

## Safety & Legal Notice

This tool is intended for **authorized security testing only**. Always:
- Obtain proper written authorization before testing
- Test only systems you own or have explicit permission to test
- Follow responsible disclosure practices
- Comply with all applicable laws and regulations

**The authors are not responsible for any misuse or damage caused by this tool.**

## License

This project is for educational purposes only.

## Credits

ATOMIC Framework v8.2 — ULTIMATE EDITION | Codename: PHOENIX
