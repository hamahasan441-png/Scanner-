#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v10.0 - ULTIMATE EDITION
Main Entry Point - Termux Optimized
⚠️ FOR AUTHORIZED TESTING ONLY ⚠️
"""

import sys
import os
import argparse
import time
import warnings
from datetime import datetime

# Suppress warnings
warnings.filterwarnings('ignore')

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import Config, Colors
from core.engine import AtomicEngine
from core.banner import print_banner
from utils.helpers import check_dependencies, install_deps


def _parse_csv(value):
    """Parse comma-separated CLI values into a trimmed list."""
    if not value:
        return []
    return [x.strip() for x in value.split(',') if x.strip()]


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description=f'{Colors.BOLD}ATOMIC FRAMEWORK v{Config.VERSION} - ULTIMATE EDITION{Colors.RESET}',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.CYAN}Examples:{Colors.RESET}
  {Colors.GREEN}%(prog)s -t https://target.com{Colors.RESET}                    # Basic scan
  {Colors.GREEN}%(prog)s -t https://target.com --full{Colors.RESET}             # Full scan with all modules
  {Colors.GREEN}%(prog)s -t https://target.com -d 5 -T 100{Colors.RESET}        # Deep scan with 100 threads
  {Colors.GREEN}%(prog)s -t https://target.com --shell{Colors.RESET}            # Try to upload shell
  {Colors.GREEN}%(prog)s -t https://target.com --dump{Colors.RESET}             # Dump database
  {Colors.GREEN}%(prog)s -t https://target.com --evasion insane{Colors.RESET}   # Maximum evasion
  {Colors.GREEN}%(prog)s --list-scans{Colors.RESET}                           # List previous scans
  {Colors.GREEN}%(prog)s --report <scan_id>{Colors.RESET}                     # Generate report
  {Colors.GREEN}%(prog)s --shell-manager{Colors.RESET}                        # Manage active shells

{Colors.CYAN}Burp Suite Tools:{Colors.RESET}
  {Colors.GREEN}%(prog)s --proxy-server{Colors.RESET}                         # Start intercepting proxy
  {Colors.GREEN}%(prog)s --proxy-server --proxy-intercept{Colors.RESET}       # Proxy with intercept mode
  {Colors.GREEN}%(prog)s --repeater < request.txt{Colors.RESET}              # Replay raw HTTP request
  {Colors.GREEN}%(prog)s -t https://target.com?id=1 --intruder{Colors.RESET} # Intruder attack
  {Colors.GREEN}%(prog)s --decode "dGVzdA=="{Colors.RESET}                   # Smart decode data
  {Colors.GREEN}%(prog)s --encode "test" --encode-type base64{Colors.RESET}  # Encode data
  {Colors.GREEN}%(prog)s --sequencer < tokens.txt{Colors.RESET}              # Analyze token randomness
  {Colors.GREEN}%(prog)s --compare resp1.txt resp2.txt{Colors.RESET}         # Compare responses

{Colors.CYAN}AI-Powered Analysis (Qwen2.5-7B Local LLM):{Colors.RESET}
  {Colors.GREEN}%(prog)s --download-model{Colors.RESET}                           # Download Qwen2.5-7B model (~4.7 GB)
  {Colors.GREEN}%(prog)s -t https://target.com --local-llm{Colors.RESET}          # Scan with AI analysis
  {Colors.GREEN}%(prog)s -t https://target.com --local-llm --llm-model /path/to/model.gguf{Colors.RESET}

{Colors.CYAN}Termux Installation:{Colors.RESET}
  pkg update && pkg upgrade -y
  pkg install python clang libffi openssl git -y
  pip install -r requirements.txt
  pip install llama-cpp-python         # For local AI (Qwen2.5-7B)
  python main.py --download-model      # Auto-download model

{Colors.YELLOW}⚠️  FOR AUTHORIZED TESTING ONLY ⚠️{Colors.RESET}
        """
    )
    
    # Target options
    parser.add_argument('-t', '--target', 
                       help='Target URL to scan')
    parser.add_argument('-f', '--file', 
                       help='File containing list of targets')
    parser.add_argument('--urls', 
                       help='Comma-separated list of URLs')
    parser.add_argument('--authorized', action='store_true',
                       help='Confirm you are authorized to test the specified targets')
    parser.add_argument('--strict-scope', action='store_true',
                       help='Enforce strict target scope (do not auto-expand from target host)')
    parser.add_argument('--allow-domain',
                       help='Comma-separated allowed domains for strict scope enforcement')
    parser.add_argument('--allow-path',
                       help='Comma-separated allowed path prefixes (e.g., /api,/v1)')
    parser.add_argument('--exclude-path',
                       help='Comma-separated excluded path prefixes (e.g., /admin,/internal)')
    parser.add_argument('--regulated-mission', action='store_true',
                       help='Enable regulated mission order (safe baseline -> prioritized scan -> verification/report)')
    
    # Scan options
    parser.add_argument('-d', '--depth', type=int, default=3,
                       help='Crawl depth (1-10, default: 3)')
    parser.add_argument('-T', '--threads', type=int, default=50,
                       help='Number of threads (default: 50)')
    parser.add_argument('--timeout', type=int, default=15,
                       help='Request timeout in seconds (default: 15)')
    parser.add_argument('--delay', type=float, default=0.1,
                       help='Delay between requests (default: 0.1)')
    
    # Module options
    parser.add_argument('--full', action='store_true',
                       help='Enable all modules')
    parser.add_argument('--point-to-point', action='store_true',
                       help='Ultimate scan: enable every module, recon, exploitation, '
                            'network scanning, and post-exploitation for complete '
                            'point-to-point coverage')
    parser.add_argument('--turbo', action='store_true',
                       help='Maximum parallelism mode: parallel baseline capture, '
                            'concurrent worker dispatch, and aggressive threading '
                            'for fastest possible scan speed')
    parser.add_argument('--sqli', action='store_true',
                       help='Enable SQL Injection module')
    parser.add_argument('--xss', action='store_true',
                       help='Enable XSS module')
    parser.add_argument('--lfi', action='store_true',
                       help='Enable LFI/RFI module')
    parser.add_argument('--cmdi', action='store_true',
                       help='Enable Command Injection module')
    parser.add_argument('--ssrf', action='store_true',
                       help='Enable SSRF module')
    parser.add_argument('--ssti', action='store_true',
                       help='Enable SSTI module')
    parser.add_argument('--xxe', action='store_true',
                       help='Enable XXE module')
    parser.add_argument('--idor', action='store_true',
                       help='Enable IDOR module')
    parser.add_argument('--nosql', action='store_true',
                       help='Enable NoSQL Injection module')
    parser.add_argument('--cors', action='store_true',
                       help='Enable CORS misconfiguration check')
    parser.add_argument('--jwt', action='store_true',
                       help='Enable JWT security check')
    parser.add_argument('--upload', action='store_true',
                       help='Enable file upload tests')
    parser.add_argument('--open-redirect', action='store_true',
                       help='Enable open redirect detection')
    parser.add_argument('--crlf', action='store_true',
                       help='Enable CRLF injection detection')
    parser.add_argument('--hpp', action='store_true',
                       help='Enable HTTP parameter pollution detection')
    parser.add_argument('--graphql', action='store_true',
                       help='Enable GraphQL injection detection')
    parser.add_argument('--proto-pollution', action='store_true',
                       help='Enable prototype pollution detection')
    parser.add_argument('--race', action='store_true',
                       help='Enable race condition detection')
    parser.add_argument('--websocket', action='store_true',
                       help='Enable WebSocket injection detection')
    parser.add_argument('--deser', action='store_true',
                       help='Enable deserialization vulnerability detection')
    parser.add_argument('--cloud-scan', action='store_true',
                       help='Enable cloud security scanning (S3 buckets, metadata, IAM, Kubernetes)')
    parser.add_argument('--osint', action='store_true',
                       help='Enable OSINT reconnaissance')
    parser.add_argument('--fuzz', action='store_true',
                       help='Enable fuzzing (parameter, header, method, vhost)')
    parser.add_argument('--sqlmap', action='store_true',
                       help='Enable sqlmap integration for deep SQLi/CMDi testing (requires sqlmap installed)')
    
    # Exploitation options
    parser.add_argument('--shell', action='store_true',
                       help='Attempt to upload web shell')
    parser.add_argument('--dump', action='store_true',
                       help='Attempt to dump database')
    parser.add_argument('--os-shell', action='store_true',
                       help='Attempt to get OS shell')
    parser.add_argument('--brute', action='store_true',
                       help='Enable brute force attacks')
    parser.add_argument('--exploit-chain', action='store_true',
                       help='Enable exploit chaining')
    parser.add_argument('--auto-exploit', action='store_true',
                       help='AI-driven post-exploitation: auto extract data, upload shells, enumerate systems')

    # Local LLM options (Qwen2.5-7B)
    parser.add_argument('--local-llm', action='store_true',
                       help='Enable local Qwen2.5-7B LLM for AI-powered analysis '
                            '(auto-downloads model on first use)')
    parser.add_argument('--download-model', action='store_true',
                       help='Download the Qwen2.5-7B GGUF model without scanning')
    parser.add_argument('--llm-model', type=str, default=None,
                       help='Path to custom GGUF model file (default: auto-download Qwen2.5-7B)')
    parser.add_argument('--llm-threads', type=int, default=None,
                       help='Number of CPU threads for LLM inference')
    parser.add_argument('--llm-ctx', type=int, default=None,
                       help='Context window size for LLM (default: 2048)')
    parser.add_argument('--llm-gpu-layers', type=int, default=0,
                       help='Number of layers to offload to GPU (default: 0, CPU-only)')

    # Evasion options
    parser.add_argument('-e', '--evasion', 
                       choices=['none', 'low', 'medium', 'high', 'insane', 'stealth'],
                       default='none',
                       help='Evasion level (default: none)')
    parser.add_argument('--waf-bypass', action='store_true',
                       help='Enable WAF bypass techniques')
    parser.add_argument('--tor', action='store_true',
                       help='Route through Tor network')
    parser.add_argument('--proxy', 
                       help='Use proxy (format: http://host:port)')
    parser.add_argument('--rotate-proxy', action='store_true',
                       help='Rotate proxies automatically')
    parser.add_argument('--rotate-ua', action='store_true',
                       help='Rotate User-Agent automatically')
    
    # Reconnaissance options
    parser.add_argument('--recon', action='store_true',
                       help='Enable reconnaissance')
    parser.add_argument('--subdomains', action='store_true',
                       help='Enumerate subdomains')
    parser.add_argument('--ports', 
                       help='Port scan (e.g., 80,443,8080 or 1-1000)')
    parser.add_argument('--tech-detect', action='store_true',
                       help='Detect technologies')
    parser.add_argument('--dir-brute', action='store_true',
                       help='Directory brute force')
    parser.add_argument('--discovery', action='store_true',
                       help='Enable target discovery & enumeration (robots.txt, sitemap, smart analysis)')
    parser.add_argument('--net-exploit', action='store_true',
                       help='Enable network exploit scanning (maps open ports/services to known CVEs)')
    parser.add_argument('--tech-exploit', action='store_true',
                       help='Enable technology exploit scanning (maps detected technologies to known CVEs)')

    # Packet-level network scanning (Scapy)
    parser.add_argument('--scapy', action='store_true',
                       help='Enable Scapy packet-level network crawling and OS fingerprinting')
    parser.add_argument('--stealth-scan', action='store_true',
                       help='Enable stealthy SYN port scanning via Scapy')
    parser.add_argument('--arp-discovery', action='store_true',
                       help='Enable ARP-based local network host discovery')
    parser.add_argument('--dns-recon', action='store_true',
                       help='Enable DNS reconnaissance (zone transfer, subdomain brute, record enumeration)')
    parser.add_argument('--scapy-vuln-scan', action='store_true',
                       help='Enable Scapy packet-level vulnerability scanning (SVD-001 to SVD-008)')
    parser.add_argument('--scapy-attack-chain', action='store_true',
                       help='Enable Scapy network attack chain templates')

    # Shield & Origin detection
    parser.add_argument('--shield-detect', action='store_true',
                       help='Enable CDN/WAF shield detection (Cloudflare, Akamai, Fastly, CloudFront, Sucuri)')
    parser.add_argument('--real-ip', action='store_true',
                       help='Enable real IP / origin server discovery (behind CDN)')
    parser.add_argument('--agent-scan', action='store_true',
                       help='Enable autonomous agent scanner (goal-driven with pivot detection)')
    parser.add_argument('--passive-recon', action='store_true',
                       help='Enable Phase 5 passive recon fan-out (Wayback, Common Crawl CDX, merged discovery)')
    parser.add_argument('--enrich', action='store_true',
                       help='Enable Phase 6-7 intelligence enrichment and attack surface prioritization')
    parser.add_argument('--chain-detect', action='store_true',
                       help='Enable Phase 9 exploit chain detection and CVSS auto-scoring')
    parser.add_argument('--exploit-search', action='store_true',
                       help='Enable Phase 9B exploit reference searcher (ExploitDB, Metasploit, Nuclei, CISA KEV)')
    parser.add_argument('--attack-map', action='store_true',
                       help='Enable Phase 11 exploit-aware attack map generation')
    parser.add_argument('--show-plan', action='store_true',
                       help='Display visual scan execution plan before scanning')
    
    # Report options
    parser.add_argument('--report', 
                       help='Generate report for scan ID')
    parser.add_argument('--format', 
                       choices=['json', 'csv', 'html', 'txt', 'pdf', 'xml', 'sarif', 'all'],
                       default='html',
                       help='Report format (default: html)')
    parser.add_argument('--list-scans', action='store_true',
                       help='List all scans')
    parser.add_argument('--output', '-o',
                       help='Output directory for reports')
    
    # Shell management
    parser.add_argument('--shell-manager', action='store_true',
                       help='Launch interactive shell manager')
    parser.add_argument('--shell-id',
                       help='Shell ID to interact with')
    parser.add_argument('--shell-cmd',
                       help='Command to execute on shell')
    
    # Utility options
    parser.add_argument('--install-deps', action='store_true',
                       help='Install all dependencies')
    parser.add_argument('--check-deps', action='store_true',
                       help='Check dependencies')
    parser.add_argument('--update', action='store_true',
                       help='Update framework')
    parser.add_argument('--clear-db', action='store_true',
                       help='Clear database')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Quiet mode')
    parser.add_argument('--rules',
                       help='Path to scanner rules YAML file (default: scanner_rules.yaml)')
    
    # Web dashboard
    parser.add_argument('--web', action='store_true',
                       help='Launch Flask web dashboard')
    parser.add_argument('--web-host', default='0.0.0.0',
                       help='Web dashboard host (default: 0.0.0.0)')
    parser.add_argument('--web-port', type=int, default=5000,
                       help='Web dashboard port (default: 5000)')
    
    # Burp Suite-style tools
    parser.add_argument('--proxy-server', action='store_true',
                       help='Launch intercepting proxy server')
    parser.add_argument('--proxy-port', type=int, default=8080,
                       help='Proxy server port (default: 8080)')
    parser.add_argument('--proxy-intercept', action='store_true',
                       help='Enable request interception on proxy')
    parser.add_argument('--repeater', action='store_true',
                       help='Launch interactive repeater (send raw HTTP request from stdin)')
    parser.add_argument('--intruder', action='store_true',
                       help='Launch intruder attack mode')
    parser.add_argument('--intruder-type',
                       choices=['sniper', 'battering_ram', 'pitchfork', 'cluster_bomb'],
                       default='sniper',
                       help='Intruder attack type (default: sniper)')
    parser.add_argument('--intruder-payloads',
                       help='File containing payloads (one per line)')
    parser.add_argument('--decode', metavar='DATA',
                       help='Decode data (auto-detect encoding)')
    parser.add_argument('--encode', metavar='DATA',
                       help='Encode data')
    parser.add_argument('--encode-type',
                       choices=['url', 'double_url', 'base64', 'hex',
                                'html_entities', 'unicode_escape', 'rot13'],
                       default='url',
                       help='Encoding type for --encode (default: url)')
    parser.add_argument('--sequencer', action='store_true',
                       help='Analyze token randomness from stdin (one token per line)')
    parser.add_argument('--compare', nargs=2, metavar='FILE',
                       help='Compare two response files')

    # External tool integration
    parser.add_argument('--nmap', action='store_true',
                       help='Run Nmap network scan on target (requires nmap installed)')
    parser.add_argument('--nmap-ports', default='1-1000',
                       help='Port specification for Nmap (default: 1-1000)')
    parser.add_argument('--nmap-type',
                       choices=['quick', 'service', 'vuln', 'full'],
                       default='service',
                       help='Nmap scan type (default: service)')
    parser.add_argument('--nuclei', action='store_true',
                       help='Run Nuclei template scan on target (requires nuclei installed)')
    parser.add_argument('--nuclei-severity',
                       help='Nuclei severity filter (critical,high,medium,low,info)')
    parser.add_argument('--nuclei-tags',
                       help='Nuclei template tags filter (e.g., cve,owasp)')
    parser.add_argument('--nuclei-templates',
                       help='Custom Nuclei template directory or file path')
    parser.add_argument('--nuclei-builtin', action='store_true',
                       help='Include ATOMIC Framework built-in Nuclei templates '
                            '(exposure, misconfig, takeover, vulnerabilities)')
    parser.add_argument('--nuclei-list-templates', action='store_true',
                       help='List all built-in Nuclei templates and exit')
    parser.add_argument('--nikto', action='store_true',
                       help='Run Nikto web server scan (requires nikto installed)')
    parser.add_argument('--whatweb', action='store_true',
                       help='Run WhatWeb fingerprinting (requires whatweb installed)')
    parser.add_argument('--subfinder', action='store_true',
                       help='Run Subfinder subdomain enumeration (requires subfinder installed)')
    parser.add_argument('--tools-check', action='store_true',
                       help='Check availability of all external security tools')
    parser.add_argument('--tools-install', action='store_true',
                       help='Download and install missing external security tools')
    parser.add_argument('--tool', type=str, default='',
                       help='Specific tool name for --tools-install (e.g. nmap, nuclei, httpx)')

    # Recon Arsenal — Advanced Discovery & Gathering Tools
    parser.add_argument('--amass', action='store_true',
                       help='Run OWASP Amass subdomain enumeration (requires amass)')
    parser.add_argument('--amass-mode', choices=['passive', 'active'], default='passive',
                       help='Amass enumeration mode (default: passive)')
    parser.add_argument('--httpx', action='store_true',
                       help='Run httpx HTTP probing & tech detection (requires httpx)')
    parser.add_argument('--katana', action='store_true',
                       help='Run Katana web crawler (requires katana)')
    parser.add_argument('--katana-depth', type=int, default=3,
                       help='Katana crawl depth (default: 3)')
    parser.add_argument('--dnsx', action='store_true',
                       help='Run dnsx DNS toolkit (requires dnsx)')
    parser.add_argument('--ffuf', action='store_true',
                       help='Run ffuf web fuzzer (requires ffuf)')
    parser.add_argument('--ffuf-wordlist',
                       help='Wordlist for ffuf fuzzing')
    parser.add_argument('--gau', action='store_true',
                       help='Run gau URL harvesting from web archives (requires gau)')
    parser.add_argument('--waybackurls', action='store_true',
                       help='Run waybackurls Wayback Machine URL fetcher (requires waybackurls)')
    parser.add_argument('--gobuster', action='store_true',
                       help='Run Gobuster directory/DNS brute-force (requires gobuster)')
    parser.add_argument('--gobuster-wordlist',
                       help='Wordlist for Gobuster')
    parser.add_argument('--feroxbuster', action='store_true',
                       help='Run Feroxbuster recursive content discovery (requires feroxbuster)')
    parser.add_argument('--masscan', action='store_true',
                       help='Run Masscan ultra-fast port scanner (requires masscan)')
    parser.add_argument('--masscan-ports', default='1-65535',
                       help='Port specification for Masscan (default: 1-65535)')
    parser.add_argument('--masscan-rate', type=int, default=1000,
                       help='Masscan packets per second (default: 1000)')
    parser.add_argument('--rustscan', action='store_true',
                       help='Run RustScan fast port scanner (requires rustscan)')
    parser.add_argument('--hakrawler', action='store_true',
                       help='Run Hakrawler web crawler (requires hakrawler)')
    parser.add_argument('--arjun', action='store_true',
                       help='Run Arjun HTTP parameter discovery (requires arjun)')
    parser.add_argument('--paramspider', action='store_true',
                       help='Run ParamSpider parameter mining (requires paramspider)')
    parser.add_argument('--dirsearch', action='store_true',
                       help='Run Dirsearch web path scanner (requires dirsearch)')
    parser.add_argument('--recon-arsenal', action='store_true',
                       help='Run full recon arsenal (all available gathering/discovery tools)')

    # Compliance & reporting
    parser.add_argument('--compliance', action='store_true',
                       help='Run compliance analysis after scan (OWASP, PCI-DSS, NIST, CIS)')
    parser.add_argument('--compliance-frameworks',
                       help='Comma-separated compliance frameworks (owasp,pci_dss,nist,cis,sans)')

    # Scheduling
    parser.add_argument('--schedule',
                       help='Schedule recurring scan (interval in minutes, e.g., "60" for hourly)')
    parser.add_argument('--schedule-cron',
                       help='Schedule scan with cron expression (e.g., "0 */6 * * *" for every 6h)')
    parser.add_argument('--schedule-name',
                       help='Name for the scheduled scan')

    # Notifications
    parser.add_argument('--notify-webhook',
                       help='Webhook URL for scan notifications')
    parser.add_argument('--notify-format',
                       choices=['generic', 'slack', 'discord', 'teams'],
                       default='generic',
                       help='Webhook notification format (default: generic)')

    args = parser.parse_args()
    
    # Print banner
    if not args.quiet:
        print_banner()

    # Check external tools availability
    if args.tools_check:
        from utils.tool_downloader import print_tools_status
        print_tools_status()
        return

    # Install external security tools
    if args.tools_install:
        from utils.tool_downloader import install_tool, install_all_tools, TOOL_REGISTRY
        if args.tool:
            tool_name = args.tool.lower().strip()
            if tool_name not in TOOL_REGISTRY:
                print(f"{Colors.error(f'Unknown tool: {tool_name}')}")
                print(f"{Colors.info('Available tools: ' + ', '.join(sorted(TOOL_REGISTRY.keys())))}")
                sys.exit(1)
            install_tool(tool_name)
        else:
            install_all_tools()
        return

    # Download Qwen2.5-7B model (standalone)
    if args.download_model:
        from core.local_llm import download_model, LocalLLM
        download_model()
        # Also install backend if missing
        if not LocalLLM.is_available():
            LocalLLM.install_backend()
        return

    # External tool standalone runs
    if args.nmap and args.target:
        from core.tool_integrator import NmapAdapter
        from urllib.parse import urlparse
        nmap = NmapAdapter()
        if not nmap.is_available():
            print(f"{Colors.error('Nmap not installed. Install with: apt install nmap')}")
            sys.exit(1)
        hostname = urlparse(args.target).hostname or args.target
        print(f"{Colors.info(f'Running Nmap {args.nmap_type} scan on {hostname}...')}")
        result = nmap.run(hostname, ports=args.nmap_ports, scan_type=args.nmap_type)
        if result.success:
            print(f"{Colors.success(f'Nmap complete: {len(result.findings)} findings in {result.duration_seconds}s')}")
            for f in result.findings:
                if f.get('type') == 'open_port':
                    print(f"  {Colors.CYAN}{f['port']}/{f['protocol']}{Colors.RESET} - {f['service']} {f.get('product','')} {f.get('version','')}")
                elif f.get('type') == 'vulnerability':
                    print(f"  {Colors.RED}[VULN]{Colors.RESET} Port {f['port']}: {f['script']} - {f.get('details','')[:100]}")
        else:
            print(f"{Colors.error(f'Nmap failed: {result.error}')}")
        if not args.nuclei and not args.nikto:
            return

    # ── Nuclei template listing ──
    if getattr(args, 'nuclei_list_templates', False):
        from core.tool_integrator import NucleiAdapter
        templates = NucleiAdapter.list_builtin_templates()
        print(f"\n{Colors.CYAN}  ATOMIC Framework Built-in Nuclei Templates{Colors.RESET}")
        print(f"  {'='*50}")
        print(f"  Path: {NucleiAdapter.builtin_templates_path()}")
        print(f"  Total: {len(templates)} templates\n")
        for t in templates:
            print(f"    {t}")
        print()
        return

    if args.nuclei and args.target:
        from core.tool_integrator import NucleiAdapter
        nuclei = NucleiAdapter()
        if not nuclei.is_available():
            print(f"{Colors.error('Nuclei not installed. Install from: https://github.com/projectdiscovery/nuclei')}")
            sys.exit(1)
        use_builtin = getattr(args, 'nuclei_builtin', False)
        custom_templates = getattr(args, 'nuclei_templates', '') or ''
        tpl_desc = []
        if custom_templates:
            tpl_desc.append(f'custom: {custom_templates}')
        if use_builtin:
            tpl_desc.append(f'builtin: {len(nuclei.list_builtin_templates())} templates')
        tpl_info = f' ({", ".join(tpl_desc)})' if tpl_desc else ''
        print(f"{Colors.info(f'Running Nuclei scan on {args.target}{tpl_info}...')}")
        result = nuclei.run(
            args.target,
            templates=custom_templates,
            severity=args.nuclei_severity or '',
            tags=args.nuclei_tags or '',
            use_builtin=use_builtin,
        )
        if result.success:
            print(f"{Colors.success(f'Nuclei complete: {len(result.findings)} findings in {result.duration_seconds}s')}")
            for f in result.findings:
                sev_color = Colors.RED if f.get('severity') in ('critical', 'high') else Colors.YELLOW
                print(f"  {sev_color}[{f.get('severity','?').upper()}]{Colors.RESET} {f.get('name','')} - {f.get('matched_at','')}")
        else:
            print(f"{Colors.error(f'Nuclei failed: {result.error}')}")
        if not args.nikto:
            return

    if args.nikto and args.target:
        from core.tool_integrator import NiktoAdapter
        nikto = NiktoAdapter()
        if not nikto.is_available():
            print(f"{Colors.error('Nikto not installed. Install with: apt install nikto')}")
            sys.exit(1)
        print(f"{Colors.info(f'Running Nikto scan on {args.target}...')}")
        result = nikto.run(args.target)
        if result.success:
            print(f"{Colors.success(f'Nikto complete: {len(result.findings)} findings in {result.duration_seconds}s')}")
            for f in result.findings:
                print(f"  {f.get('msg', f.get('url', ''))}")
        else:
            print(f"{Colors.error(f'Nikto failed: {result.error}')}")
        return

    if args.whatweb and args.target:
        from core.tool_integrator import WhatWebAdapter
        whatweb = WhatWebAdapter()
        if not whatweb.is_available():
            print(f"{Colors.error('WhatWeb not installed. Install with: gem install whatweb')}")
            sys.exit(1)
        print(f"{Colors.info(f'Running WhatWeb on {args.target}...')}")
        result = whatweb.run(args.target)
        if result.success:
            print(f"{Colors.success(f'WhatWeb complete: {len(result.findings)} technologies detected')}")
            for f in result.findings:
                ver = f' v{f["version"]}' if f.get('version') else ''
                print(f"  {Colors.CYAN}{f['technology']}{Colors.RESET}{ver}")
        else:
            print(f"{Colors.error(f'WhatWeb failed: {result.error}')}")
        return

    if args.subfinder and args.target:
        from core.tool_integrator import SubfinderAdapter
        from urllib.parse import urlparse
        subfinder = SubfinderAdapter()
        if not subfinder.is_available():
            print(f"{Colors.error('Subfinder not installed. Install from: https://github.com/projectdiscovery/subfinder')}")
            sys.exit(1)
        domain = urlparse(args.target).hostname or args.target
        print(f"{Colors.info(f'Running Subfinder on {domain}...')}")
        result = subfinder.run(domain)
        if result.success:
            subs = result.parsed_data.get('subdomains', [])
            print(f"{Colors.success(f'Subfinder complete: {len(subs)} subdomains found')}")
            for s in subs:
                print(f"  {s}")
        else:
            print(f"{Colors.error(f'Subfinder failed: {result.error}')}")
        return

    # ---- Recon Arsenal standalone handlers ----
    _recon_arsenal_flags = [
        'amass', 'httpx', 'katana', 'dnsx', 'ffuf', 'gau', 'waybackurls',
        'gobuster', 'feroxbuster', 'masscan', 'rustscan', 'hakrawler',
        'arjun', 'paramspider', 'dirsearch', 'recon_arsenal',
    ]
    _any_recon = any(getattr(args, flag, False) for flag in _recon_arsenal_flags)

    if _any_recon and args.target:
        from core.recon_arsenal import ReconArsenal
        from urllib.parse import urlparse
        arsenal = ReconArsenal()
        domain = urlparse(args.target).hostname or args.target

        def _print_recon_result(name, result):
            if result.success:
                print(f"{Colors.success(f'{name} complete: {len(result.findings)} findings in {result.duration_seconds}s')}")
                for f in result.findings[:20]:
                    detail = f.get('url', '') or f.get('subdomain', '') or f.get('host', '') or f.get('ip', '') or str(f)
                    print(f"  {detail[:120]}")
                if len(result.findings) > 20:
                    print(f"  ... and {len(result.findings) - 20} more")
            else:
                print(f"{Colors.error(f'{name} failed: {result.error}')}")

        if args.recon_arsenal:
            print(f"{Colors.info(f'Running full Recon Arsenal on {args.target}...')}")
            results = arsenal.run_full_recon(args.target, domain=domain)
            for name, res in results.items():
                _print_recon_result(name.upper(), res)
            total = sum(len(r.findings) for r in results.values())
            print(f"\n{Colors.success(f'Recon Arsenal complete: {total} total findings from {len(results)} tools')}")
            return

        if args.amass:
            print(f"{Colors.info(f'Running Amass ({args.amass_mode}) on {domain}...')}")
            _print_recon_result('Amass', arsenal.amass.run(domain, mode=args.amass_mode))

        if args.httpx:
            print(f"{Colors.info(f'Running httpx on {args.target}...')}")
            _print_recon_result('httpx', arsenal.httpx.run(args.target))

        if args.katana:
            print(f"{Colors.info(f'Running Katana on {args.target}...')}")
            _print_recon_result('Katana', arsenal.katana.run(args.target, depth=args.katana_depth))

        if args.dnsx:
            print(f"{Colors.info(f'Running dnsx on {domain}...')}")
            _print_recon_result('dnsx', arsenal.dnsx.run(domain))

        if args.ffuf:
            print(f"{Colors.info(f'Running ffuf on {args.target}...')}")
            _print_recon_result('ffuf', arsenal.ffuf.run(args.target, wordlist=args.ffuf_wordlist or ''))

        if args.gau:
            print(f"{Colors.info(f'Running gau on {domain}...')}")
            _print_recon_result('gau', arsenal.gau.run(domain))

        if args.waybackurls:
            print(f"{Colors.info(f'Running waybackurls on {domain}...')}")
            _print_recon_result('waybackurls', arsenal.waybackurls.run(domain))

        if args.gobuster:
            print(f"{Colors.info(f'Running Gobuster on {args.target}...')}")
            _print_recon_result('Gobuster', arsenal.gobuster.run(args.target, wordlist=args.gobuster_wordlist or ''))

        if args.feroxbuster:
            print(f"{Colors.info(f'Running Feroxbuster on {args.target}...')}")
            _print_recon_result('Feroxbuster', arsenal.feroxbuster.run(args.target))

        if args.masscan:
            print(f"{Colors.info(f'Running Masscan on {domain}...')}")
            _print_recon_result('Masscan', arsenal.masscan.run(domain, ports=args.masscan_ports, rate=args.masscan_rate))

        if args.rustscan:
            print(f"{Colors.info(f'Running RustScan on {domain}...')}")
            _print_recon_result('RustScan', arsenal.rustscan.run(domain))

        if args.hakrawler:
            print(f"{Colors.info(f'Running Hakrawler on {args.target}...')}")
            _print_recon_result('Hakrawler', arsenal.hakrawler.run(args.target))

        if args.arjun:
            print(f"{Colors.info(f'Running Arjun on {args.target}...')}")
            _print_recon_result('Arjun', arsenal.arjun.run(args.target))

        if args.paramspider:
            print(f"{Colors.info(f'Running ParamSpider on {domain}...')}")
            _print_recon_result('ParamSpider', arsenal.paramspider.run(domain))

        if args.dirsearch:
            print(f"{Colors.info(f'Running Dirsearch on {args.target}...')}")
            _print_recon_result('Dirsearch', arsenal.dirsearch.run(args.target))

        return

    # Launch web dashboard
    if args.web:
        try:
            from web.app import create_app
            _, run_app = create_app(host=args.web_host, port=args.web_port)
            run_app()
        except ImportError:
            print(f"{Colors.error('Flask not installed. Run: pip install flask flask-cors')}")
            sys.exit(1)
        return
    
    # Burp Suite-style tool handlers
    if args.proxy_server:
        from core.proxy import InterceptProxy
        proxy = InterceptProxy(
            host='127.0.0.1', port=args.proxy_port,
            intercept=args.proxy_intercept,
        )
        print(f"{Colors.info(f'Starting intercepting proxy on 127.0.0.1:{args.proxy_port}')}")
        if args.proxy_intercept:
            print(f"{Colors.warning('Intercept mode enabled')}")
        proxy.start()
        try:
            while proxy.is_running:
                time.sleep(1)
        except KeyboardInterrupt:
            proxy.stop()
            print(f"\n{Colors.info('Proxy stopped')}")
        return

    if args.repeater:
        from core.repeater import Repeater
        repeater = Repeater(
            timeout=args.timeout,
            proxy=args.proxy,
        )
        print(f"{Colors.info('Repeater ready. Paste raw HTTP request then press Ctrl-D:')}")
        raw = sys.stdin.read()
        if raw.strip():
            resp = repeater.send_raw(raw)
            print(f"\n{Colors.BOLD}HTTP/{resp.status_code}{Colors.RESET}")
            for k, v in resp.headers.items():
                print(f"{Colors.CYAN}{k}{Colors.RESET}: {v}")
            print(f"\n{resp.body[:2000]}")
            print(f"\n{Colors.info(f'Elapsed: {resp.elapsed:.3f}s | Size: {resp.size} bytes')}")
        else:
            print(f"{Colors.error('No request data provided')}")
        return

    if args.intruder:
        if not args.target:
            print(f"{Colors.error('Intruder requires -t/--target')}")
            sys.exit(1)
        from core.intruder import Intruder, MARKER
        intruder = Intruder(
            timeout=args.timeout,
            proxy=args.proxy,
            threads=args.threads,
            delay=args.delay,
        )
        intruder.set_target('GET', args.target)
        intruder.set_attack_type(args.intruder_type)
        payloads = []
        if args.intruder_payloads and os.path.isfile(args.intruder_payloads):
            with open(args.intruder_payloads, 'r') as fp:
                payloads = [line.strip() for line in fp if line.strip()]
        if not payloads:
            from config import Payloads as P
            payloads = P.XSS_PAYLOADS[:10] + P.SQLI_ERROR_BASED[:10]
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(args.target)
        qs = parse_qs(parsed.query)
        if qs:
            for param in qs:
                marker = f'{MARKER}{param}{MARKER}'
                intruder.set_positions([{
                    'name': param, 'location': 'url', 'marker': marker,
                }])
                intruder.add_payload_set(param, payloads)
        else:
            intruder.set_positions([{
                'name': 'FUZZ', 'location': 'url',
                'marker': f'{MARKER}FUZZ{MARKER}',
            }])
            intruder.add_payload_set('FUZZ', payloads)
            new_url = args.target.rstrip('/') + f'/{MARKER}FUZZ{MARKER}'
            intruder.set_target('GET', new_url)

        print(f"{Colors.info(f'Intruder attacking {args.target} [{args.intruder_type}]')}")
        results = intruder.attack()
        print(f"\n{Colors.BOLD}{'#':<5} {'Status':<8} {'Length':<10} {'Time':<8} Payload{Colors.RESET}")
        for r in results:
            print(f"{r.index:<5} {r.status_code:<8} {r.length:<10} {r.elapsed:<8.3f} {str(r.payload)[:60]}")
        print(f"\n{Colors.success(f'Attack complete: {len(results)} requests sent')}")
        return

    if args.decode:
        from utils.decoder import Decoder
        result = Decoder.smart_decode(args.decode)
        print(f"{Colors.info('Smart decode result:')}")
        print(result)
        return

    if args.encode:
        from utils.decoder import Decoder
        result = Decoder.encode(args.encode, args.encode_type)
        print(f"{Colors.info(f'Encoded ({args.encode_type}):')}")
        print(result)
        return

    if args.sequencer:
        from utils.sequencer import Sequencer
        seq = Sequencer()
        print(f"{Colors.info('Paste tokens (one per line), then Ctrl-D:')}")
        for line in sys.stdin:
            token = line.strip()
            if token:
                seq.add_token(token)
        report = seq.generate_report()
        summary = report.get('summary', {})
        analysis = report.get('analysis', {})
        print(f"\n{Colors.BOLD}Token Sequencer Analysis{Colors.RESET}")
        print(f"  Tokens analyzed: {summary.get('token_count', 0)}")
        print(f"  Entropy: {analysis.get('entropy', 0):.4f} bits/char ({analysis.get('entropy_rating', 'N/A')})")
        chi_val = analysis.get('chi_squared', 0)
        chi_random = analysis.get('chi_squared_random', False)
        print(f"  Chi-squared: {chi_val:.2f} (random: {chi_random})")
        print(f"  Unique ratio: {analysis.get('uniqueness_ratio', 0):.2%}")
        print(f"  Predictable: {summary.get('is_predictable', False)} (confidence: {summary.get('predictability_confidence', 0):.1%})")
        reason = summary.get('predictability_reason', '')
        if reason:
            print(f"  Reason: {reason}")
        return

    if args.compare:
        from utils.comparer import Comparer
        file1, file2 = args.compare
        if not os.path.isfile(file1) or not os.path.isfile(file2):
            print(f"{Colors.error('One or both files not found')}")
            sys.exit(1)
        with open(file1, 'r') as f:
            text1 = f.read()
        with open(file2, 'r') as f:
            text2 = f.read()
        comp = Comparer()
        ratio = comp.similarity_ratio(text1, text2)
        print(f"{Colors.info(f'Similarity: {ratio:.2%}')}")
        diff = comp.diff_text(text1, text2)
        for line in diff:
            if line.startswith('+') and not line.startswith('+++'):
                print(f"{Colors.GREEN}{line}{Colors.RESET}")
            elif line.startswith('-') and not line.startswith('---'):
                print(f"{Colors.RED}{line}{Colors.RESET}")
            else:
                print(line)
        return

    # Check/Install dependencies
    if args.check_deps:
        check_dependencies()
        return
    
    if args.install_deps:
        install_deps()
        return
    
    # Handle report generation
    if args.report:
        from core.reporter import ReportGenerator
        generator = ReportGenerator(args.report)
        generator.generate_all() if args.format == 'all' else generator.generate(args.format)
        return
    
    # List scans
    if args.list_scans:
        from utils.database import list_scans
        list_scans()
        return
    
    # Clear database
    if args.clear_db:
        from utils.database import clear_database
        clear_database()
        return
    
    # Shell manager
    if args.shell_manager or args.shell_id:
        from modules.shell.manager import ShellManager
        manager = ShellManager()
        if args.shell_id:
            if args.shell_cmd:
                manager.execute_command(args.shell_id, args.shell_cmd)
            else:
                manager.interactive_shell(args.shell_id)
        else:
            manager.list_shells()
        return
    
    # Validate target
    if not args.target and not args.file and not args.urls:
        parser.print_help()
        print(f"\n{Colors.error('No target specified. Use -t, -f, or --urls')}")
        sys.exit(1)
    
    # Build configuration
    config = {
        'depth': args.depth,
        'threads': args.threads,
        'timeout': args.timeout,
        'delay': args.delay,
        'evasion': args.evasion,
        'waf_bypass': args.waf_bypass,
        'tor': args.tor,
        'proxy': args.proxy,
        'rotate_proxy': args.rotate_proxy,
        'rotate_ua': args.rotate_ua,
        'verbose': args.verbose,
        'quiet': args.quiet,
        'output_dir': args.output or Config.REPORTS_DIR,
        'rules_path': getattr(args, 'rules', None),
        'strict_scope': getattr(args, 'strict_scope', False),
        'turbo': getattr(args, 'turbo', False),
        'auto_external_tools': True,
    }

    # --point-to-point enables absolutely everything for complete coverage
    p2p = getattr(args, 'point_to_point', False)

    # Build module configuration
    modules = {
        'sqli': args.sqli or args.full or p2p,
        'xss': args.xss or args.full or p2p,
        'lfi': args.lfi or args.full or p2p,
        'cmdi': args.cmdi or args.full or p2p,
        'ssrf': args.ssrf or args.full or p2p,
        'ssti': args.ssti or args.full or p2p,
        'xxe': args.xxe or args.full or p2p,
        'idor': args.idor or args.full or p2p,
        'nosql': args.nosql or args.full or p2p,
        'cors': args.cors or args.full or p2p,
        'jwt': args.jwt or args.full or p2p,
        'upload': args.upload or args.full or p2p,
        'open_redirect': args.open_redirect or args.full or p2p,
        'crlf': args.crlf or args.full or p2p,
        'hpp': args.hpp or args.full or p2p,
        'graphql': args.graphql or args.full or p2p,
        'proto_pollution': args.proto_pollution or args.full or p2p,
        'race_condition': getattr(args, 'race', False) or args.full or p2p,
        'websocket': getattr(args, 'websocket', False) or args.full or p2p,
        'deserialization': getattr(args, 'deser', False) or args.full or p2p,
        'cloud_scan': getattr(args, 'cloud_scan', False) or args.full or p2p,
        'osint': getattr(args, 'osint', False) or args.full or p2p,
        'fuzzer': getattr(args, 'fuzz', False) or args.full or p2p,
        'sqlmap': getattr(args, 'sqlmap', False) or p2p,
        'shell': args.shell or p2p,
        'dump': args.dump or p2p,
        'os_shell': args.os_shell or p2p,
        'brute': args.brute or p2p,
        'exploit_chain': args.exploit_chain or p2p,
        'auto_exploit': args.auto_exploit or p2p,
        'recon': args.recon or args.full or p2p,
        'subdomains': args.subdomains or args.full or p2p,
        'ports': args.ports or ('1-65535' if p2p else None),
        'tech_detect': args.tech_detect or args.full or p2p,
        'dir_brute': args.dir_brute or args.full or p2p,
        'discovery': args.discovery or args.full or p2p,
        'net_exploit': getattr(args, 'net_exploit', False) or args.full or p2p,
        'tech_exploit': getattr(args, 'tech_exploit', False) or args.full or p2p,
        'shield_detect': getattr(args, 'shield_detect', False) or args.full or p2p,
        'real_ip': getattr(args, 'real_ip', False) or args.full or p2p,
        'agent_scan': getattr(args, 'agent_scan', False) or p2p,
        'passive_recon': getattr(args, 'passive_recon', False) or args.full or p2p,
        'enrich': getattr(args, 'enrich', False) or args.full or p2p,
        'chain_detect': getattr(args, 'chain_detect', False) or args.full or p2p,
        'exploit_search': getattr(args, 'exploit_search', False) or args.full or p2p,
        'attack_map': getattr(args, 'attack_map', False) or args.full or p2p,
        # Scapy packet-level network scanning
        'scapy': getattr(args, 'scapy', False) or p2p,
        'stealth_scan': getattr(args, 'stealth_scan', False) or p2p,
        'arp_discovery': getattr(args, 'arp_discovery', False) or p2p,
        'dns_recon': getattr(args, 'dns_recon', False) or p2p,
        'scapy_vuln_scan': getattr(args, 'scapy_vuln_scan', False) or p2p,
        'scapy_attack_chain': getattr(args, 'scapy_attack_chain', False) or p2p,
    }

    if args.regulated_mission:
        # Regulated mission execution order:
        # 1) boundary + shield/origin profiling
        # 2) passive recon + enrich/prioritize
        # 3) controlled workers + verification + exploit intel + attack map/report
        modules['shield_detect'] = True
        modules['real_ip'] = True
        modules['passive_recon'] = True
        modules['enrich'] = True
        modules['chain_detect'] = True
        modules['exploit_search'] = True
        modules['attack_map'] = True

    # Phase 11 (attack_map) requires Phase 9B (exploit_search) for
    # accurate exploit-aware analysis; auto-enable if missing.
    if modules.get('attack_map') and not modules.get('exploit_search'):
        modules['exploit_search'] = True
    
    # If no specific modules selected, enable basic ones
    if not any(modules.values()):
        modules['sqli'] = True
        modules['xss'] = True
        modules['lfi'] = True
        modules['cmdi'] = True
        modules['idor'] = True
        modules['cors'] = True

    # Mission boundaries / governance scope settings
    config['scope'] = {
        'allowed_domains': _parse_csv(args.allow_domain),
        'allowed_paths': _parse_csv(args.allow_path),
        'excluded_paths': _parse_csv(args.exclude_path),
    }
    if config['scope']['allowed_domains']:
        config['strict_scope'] = True

    # Governance guard: potentially intrusive scan modes require explicit
    # authorization confirmation.
    if args.regulated_mission and not args.authorized:
        print(f"{Colors.error('Authorization confirmation required: add --authorized for --regulated-mission')}")
        sys.exit(1)
    
    config['modules'] = modules

    # Local LLM configuration
    config['local_llm'] = getattr(args, 'local_llm', False) or p2p
    config['llm_model'] = getattr(args, 'llm_model', None)
    config['llm_threads'] = getattr(args, 'llm_threads', None)
    config['llm_ctx'] = getattr(args, 'llm_ctx', None)
    config['llm_gpu_layers'] = getattr(args, 'llm_gpu_layers', 0)

    # Notification configuration
    if getattr(args, 'notify_webhook', None):
        config['notify_webhook'] = args.notify_webhook
        config['notify_format'] = getattr(args, 'notify_format', 'generic')
    
    # Get targets
    targets = []
    if args.target:
        targets.append(args.target)
    if args.file:
        if not os.path.isfile(args.file):
            print(f"{Colors.error(f'File not found: {args.file}')}")
            sys.exit(1)
        try:
            with open(args.file, 'r') as f:
                targets.extend([line.strip() for line in f if line.strip()])
        except (IOError, OSError) as e:
            print(f"{Colors.error(f'Cannot read file {args.file}: {e}')}")
            sys.exit(1)
    if args.urls:
        targets.extend([url.strip() for url in args.urls.split(',')])
    
    # Validate targets have proper URL format
    from urllib.parse import urlparse
    valid_targets = []
    for t in targets:
        parsed = urlparse(t)
        if parsed.scheme in ('http', 'https') and parsed.netloc:
            valid_targets.append(t)
        else:
            print(f"{Colors.warning(f'Invalid URL skipped (must start with http:// or https://): {t}')}")
    
    if not valid_targets:
        print(f"{Colors.error('No valid targets to scan')}")
        sys.exit(1)
    targets = valid_targets

    # Ensure output directory exists
    output_dir = config.get('output_dir', Config.REPORTS_DIR)
    try:
        os.makedirs(output_dir, exist_ok=True)
    except OSError as e:
        print(f"{Colors.error(f'Cannot create output directory {output_dir}: {e}')}")
        sys.exit(1)

    # Run scan — one engine per target to isolate scan_id, findings & timing
    try:
        all_findings = []

        # Setup notifications if webhook configured
        notification_mgr = None
        if config.get('notify_webhook'):
            try:
                from core.notification import NotificationManager, WebhookChannel
                notification_mgr = NotificationManager()
                notification_mgr.register_channel(
                    'webhook',
                    WebhookChannel(url=config['notify_webhook'],
                                   format_type=config.get('notify_format', 'generic'))
                )
            except Exception:
                pass

        for target in targets:
            print(f"\n{Colors.info(f'Target: {target}')}")
            engine = AtomicEngine(config)

            # ── Initialize Local LLM if enabled ──────────────────────
            local_llm = None
            if config.get('local_llm'):
                try:
                    from core.local_llm import LocalLLM
                    local_llm = LocalLLM(
                        model_path=config.get('llm_model'),
                        n_threads=config.get('llm_threads'),
                        n_ctx=config.get('llm_ctx'),
                        n_gpu_layers=config.get('llm_gpu_layers', 0),
                        verbose=config.get('verbose', False),
                    )
                    if local_llm.ensure_ready():
                        local_llm.load()
                        engine.local_llm = local_llm
                        if not args.quiet:
                            print(f"{Colors.success('Local LLM (Qwen2.5-7B) ready for AI analysis')}")
                    else:
                        print(f"{Colors.warning('Local LLM setup incomplete — continuing without LLM')}")
                        local_llm = None
                except Exception as exc:
                    print(f"{Colors.warning(f'Local LLM init error: {exc} — continuing without LLM')}")
                    local_llm = None

            # Display scan plan if requested
            if getattr(args, 'show_plan', False):
                from core.scan_planner import ScanPlanner
                planner = ScanPlanner(engine)
                planner.display_plan(target)

            # Wire external notification manager if configured
            if notification_mgr:
                engine.notifications = notification_mgr

            engine.scan(target)

            # Generate reports only after ALL modules finished for this target
            if not args.quiet:
                print(f"\n{Colors.info('Generating reports...')}")
            engine.generate_reports()

            # Compliance analysis
            if getattr(args, 'compliance', False) and engine.findings:
                try:
                    from core.compliance import ComplianceEngine
                    compliance = ComplianceEngine()
                    frameworks = None
                    if getattr(args, 'compliance_frameworks', None):
                        frameworks = [f.strip() for f in args.compliance_frameworks.split(',')]
                    report = compliance.analyze(
                        engine.findings, scan_id=engine.scan_id, target=target,
                        frameworks=frameworks)

                    print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
                    print(f"{Colors.CYAN}  Compliance Analysis{Colors.RESET}")
                    print(f"{Colors.BOLD}{'='*60}{Colors.RESET}")
                    for fw, score in report.framework_scores.items():
                        pct = score['score_pct']
                        color = Colors.GREEN if pct >= 80 else (Colors.YELLOW if pct >= 50 else Colors.RED)
                        print(f"  {fw.upper():<10} {color}{pct:.1f}%{Colors.RESET} ({score['passing']}/{score['total_controls']} controls passing)")
                    if report.gaps:
                        print(f"\n  {Colors.RED}Top Compliance Gaps:{Colors.RESET}")
                        for gap in report.gaps[:5]:
                            print(f"    [{gap['worst_severity']}] {gap['framework'].upper()} {gap['control_id']}: "
                                  f"{gap['control_name']} ({gap['finding_count']} findings)")
                    print(f"{Colors.BOLD}{'='*60}{Colors.RESET}")
                except Exception as exc:
                    if args.verbose:
                        print(f"{Colors.warning(f'Compliance analysis error: {exc}')}")

            # ── Local LLM Scan Summary ────────────────────────────────
            if local_llm and local_llm.is_loaded and engine.findings:
                try:
                    scan_duration = getattr(engine, 'scan_duration', 0.0)
                    findings_data = []
                    for f in engine.findings:
                        fd = f if isinstance(f, dict) else getattr(f, '__dict__', {})
                        findings_data.append(fd)
                    summary = local_llm.generate_scan_summary(
                        findings_data, target, scan_duration)
                    if summary:
                        print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
                        print(f"{Colors.CYAN}  AI Scan Summary (Qwen2.5-7B){Colors.RESET}")
                        print(f"{Colors.BOLD}{'='*60}{Colors.RESET}")
                        print(f"  {summary}")
                        print(f"{Colors.BOLD}{'='*60}{Colors.RESET}")

                    # Enrich top findings with LLM analysis
                    critical_findings = [
                        f for f in findings_data
                        if f.get('severity') in ('CRITICAL', 'HIGH')
                    ][:5]
                    if critical_findings:
                        print(f"\n{Colors.info('AI analysis of top critical findings:')}")
                        for cf in critical_findings:
                            analysis = local_llm.analyze_finding(cf)
                            llm_text = analysis.get('llm_analysis', '')
                            if llm_text:
                                tech = cf.get('technique', 'Unknown')
                                print(f"\n  {Colors.RED}[{tech}]{Colors.RESET}")
                                for line in llm_text.split('\n'):
                                    print(f"    {line}")
                except Exception as exc:
                    if args.verbose:
                        print(f"{Colors.warning(f'LLM summary error: {exc}')}")

            # Unload LLM to free memory
            if local_llm:
                local_llm.unload()

            all_findings.extend(engine.findings)

        # Scheduling: if --schedule or --schedule-cron, set up recurring scan
        if getattr(args, 'schedule', None) or getattr(args, 'schedule_cron', None):
            try:
                from core.scheduler import ScanScheduler
                scheduler = ScanScheduler()
                sched_name = getattr(args, 'schedule_name', None) or f'scan-{targets[0]}'
                if getattr(args, 'schedule_cron', None):
                    entry = scheduler.add_schedule(
                        name=sched_name, target=targets[0],
                        schedule_type='cron',
                        cron_expression=args.schedule_cron,
                        config=config)
                    print(f"{Colors.success(f'Scheduled: {sched_name} (cron: {args.schedule_cron})')}")
                else:
                    interval = int(args.schedule) * 60
                    entry = scheduler.add_schedule(
                        name=sched_name, target=targets[0],
                        schedule_type='interval',
                        interval_seconds=interval,
                        config=config)
                    print(f"{Colors.success(f'Scheduled: {sched_name} (every {args.schedule} minutes)')}")
                print(f"  Next run: {entry.to_dict()['next_run']}")
                print(f"{Colors.info('Starting scheduler... (Ctrl+C to stop)')}")
                scheduler.start()
                while scheduler.is_running:
                    time.sleep(1)
            except KeyboardInterrupt:
                print(f"\n{Colors.info('Scheduler stopped')}")
                return
            except Exception as exc:
                print(f"{Colors.error(f'Scheduler error: {exc}')}")
                return

        # Overall summary when multiple targets were scanned
        if len(targets) > 1:
            print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
            print(f"{Colors.CYAN}  Overall Summary ({len(targets)} targets){Colors.RESET}")
            print(f"{Colors.BOLD}{'='*60}{Colors.RESET}")
            print(f"  Total findings: {len(all_findings)}")

            severities = {}
            for f in all_findings:
                sev = getattr(f, 'severity', 'INFO')
                severities[sev] = severities.get(sev, 0) + 1
            if severities:
                for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                    if sev in severities:
                        print(f"    {sev}: {severities[sev]}")
            print(f"{Colors.BOLD}{'='*60}{Colors.RESET}")

        print(f"\n{Colors.success('Scan completed!')}")

    except KeyboardInterrupt:
        print(f"\n{Colors.warning('Interrupted by user')}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.error(f'Error: {e}')}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
