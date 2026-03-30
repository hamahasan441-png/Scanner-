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
    
    # Report options
    parser.add_argument('--report', 
                       help='Generate report for scan ID')
    parser.add_argument('--format', 
                       choices=['json', 'csv', 'html', 'pdf', 'xml', 'all'],
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
    
    # Web dashboard
    parser.add_argument('--web', action='store_true',
                       help='Launch Flask web dashboard')
    parser.add_argument('--web-host', default='0.0.0.0',
                       help='Web dashboard host (default: 0.0.0.0)')
    parser.add_argument('--web-port', type=int, default=5000,
                       help='Web dashboard port (default: 5000)')
    
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
        'shell': args.shell,
        'dump': args.dump,
        'os_shell': args.os_shell,
        'brute': args.brute,
        'exploit_chain': args.exploit_chain,
        'recon': args.recon or args.full,
        'subdomains': args.subdomains or args.full,
        'ports': args.ports,
        'tech_detect': args.tech_detect or args.full,
        'dir_brute': args.dir_brute or args.full,
    }
    
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

    # Run scan
    try:
        engine = AtomicEngine(config)
        
        for target in targets:
            print(f"\n{Colors.info(f'Target: {target}')}")
            engine.scan(target)
        
        # Generate reports
        if not args.quiet:
            print(f"\n{Colors.info('Generating reports...')}")
        engine.generate_reports()
        
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
