#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v8.0 - ULTIMATE EDITION
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

{Colors.CYAN}Termux Installation:{Colors.RESET}
  pkg update && pkg upgrade -y
  pkg install python clang libffi openssl git -y
  pip install -r requirements.txt

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

    args = parser.parse_args()
    
    # Print banner
    if not args.quiet:
        print_banner()
    
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
    }
    
    # Build module configuration
    modules = {
        'sqli': args.sqli or args.full,
        'xss': args.xss or args.full,
        'lfi': args.lfi or args.full,
        'cmdi': args.cmdi or args.full,
        'ssrf': args.ssrf or args.full,
        'ssti': args.ssti or args.full,
        'xxe': args.xxe or args.full,
        'idor': args.idor or args.full,
        'nosql': args.nosql or args.full,
        'cors': args.cors or args.full,
        'jwt': args.jwt or args.full,
        'upload': args.upload or args.full,
        'open_redirect': args.open_redirect or args.full,
        'crlf': args.crlf or args.full,
        'hpp': args.hpp or args.full,
        'graphql': args.graphql or args.full,
        'proto_pollution': args.proto_pollution or args.full,
        'race_condition': getattr(args, 'race', False) or args.full,
        'websocket': getattr(args, 'websocket', False) or args.full,
        'deserialization': getattr(args, 'deser', False) or args.full,
        'osint': getattr(args, 'osint', False) or args.full,
        'fuzzer': getattr(args, 'fuzz', False) or args.full,
        'sqlmap': getattr(args, 'sqlmap', False),
        'shell': args.shell,
        'dump': args.dump,
        'os_shell': args.os_shell,
        'brute': args.brute,
        'exploit_chain': args.exploit_chain,
        'auto_exploit': args.auto_exploit,
        'recon': args.recon or args.full,
        'subdomains': args.subdomains or args.full,
        'ports': args.ports,
        'tech_detect': args.tech_detect or args.full,
        'dir_brute': args.dir_brute or args.full,
        'discovery': args.discovery or args.full,
        'net_exploit': getattr(args, 'net_exploit', False) or args.full,
        'tech_exploit': getattr(args, 'tech_exploit', False) or args.full,
        'shield_detect': getattr(args, 'shield_detect', False) or args.full,
        'real_ip': getattr(args, 'real_ip', False) or args.full,
        'agent_scan': getattr(args, 'agent_scan', False),
        'passive_recon': getattr(args, 'passive_recon', False) or args.full,
        'enrich': getattr(args, 'enrich', False) or args.full,
        'chain_detect': getattr(args, 'chain_detect', False) or args.full,
        'exploit_search': getattr(args, 'exploit_search', False) or args.full,
        'attack_map': getattr(args, 'attack_map', False) or args.full,
    }

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
    
    config['modules'] = modules
    
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

        for target in targets:
            print(f"\n{Colors.info(f'Target: {target}')}")
            engine = AtomicEngine(config)
            engine.scan(target)

            # Generate reports only after ALL modules finished for this target
            if not args.quiet:
                print(f"\n{Colors.info('Generating reports...')}")
            engine.generate_reports()

            all_findings.extend(engine.findings)

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
