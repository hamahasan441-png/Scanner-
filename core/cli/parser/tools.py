#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - CLI Parser: Tools & Recon Arsenal
"""
import argparse


def add_tools_arguments(parser: argparse.ArgumentParser):
    """Add external tool integration arguments."""
    g = parser.add_argument_group("External Tools (Portable)")

    # Tool runtime management
    g.add_argument("--tools-status", action="store_true", help="Show managed security-tool runtime status and exit")
    g.add_argument("--tools-doctor", action="store_true", help="Validate managed security-tool runtime and exit")
    g.add_argument("--make-portable", action="store_true", help="Copy host-installed security tools to runtime/bin and make them portable with SHA256")
    g.add_argument("--portable-tools", nargs="*", default=None, help="Specific tools to make portable (default: all found host tools)")
    g.add_argument("--tools-check", action="store_true", help="Check availability of all external security tools")
    g.add_argument("--tools-install", action="store_true", help="Download and install missing external security tools")
    g.add_argument("--tool", type=str, default="", help="Specific tool name for --tools-install (e.g. nmap, nuclei, httpx)")

    # Standalone tool wrappers (ToolIntegrator 7)
    g.add_argument("--nmap", action="store_true", help="Run Nmap network scan on target (requires nmap installed)")
    g.add_argument("--nmap-ports", default="1-1000", help="Port specification for Nmap (default: 1-1000)")
    g.add_argument("--nmap-type", choices=["quick", "service", "vuln", "full"], default="service", help="Nmap scan type")
    g.add_argument("--nuclei", action="store_true", help="Run Nuclei template-based scan (requires nuclei)")
    g.add_argument("--nuclei-severity", help="Nuclei severity filter (critical,high,medium,low,info)")
    g.add_argument("--nuclei-tags", help="Nuclei template tags filter (e.g., cve,owasp)")
    g.add_argument("--nuclei-templates", help="Custom Nuclei template directory or file path")
    g.add_argument("--nikto", action="store_true", help="Run Nikto web server scan (requires nikto installed)")
    g.add_argument("--nikto-tuning", help="Nikto tuning options")
    g.add_argument("--whatweb", action="store_true", help="Run WhatWeb technology fingerprinting (requires whatweb)")
    g.add_argument("--subfinder", action="store_true", help="Run Subfinder subdomain enumeration (requires subfinder)")

    # Recon Arsenal 15 (+ extras)
    g2 = parser.add_argument_group("Recon Arsenal (15 Advanced Tools)")
    g2.add_argument("--amass", action="store_true", help="Run OWASP Amass subdomain enumeration (requires amass)")
    g2.add_argument("--amass-mode", choices=["passive", "active"], default="passive", help="Amass mode (default: passive)")
    g2.add_argument("--httpx", action="store_true", help="Run httpx HTTP probing & tech detection (requires httpx)")
    g2.add_argument("--katana", action="store_true", help="Run Katana web crawler (requires katana)")
    g2.add_argument("--katana-depth", type=int, default=3, help="Katana crawl depth (default: 3)")
    g2.add_argument("--dnsx", action="store_true", help="Run dnsx DNS toolkit (requires dnsx)")
    g2.add_argument("--ffuf", action="store_true", help="Run ffuf web fuzzer (requires ffuf)")
    g2.add_argument("--ffuf-wordlist", help="Wordlist for ffuf fuzzing")
    g2.add_argument("--gau", action="store_true", help="Run gau URL harvesting from web archives (requires gau)")
    g2.add_argument("--waybackurls", action="store_true", help="Run waybackurls Wayback Machine URL fetcher (requires waybackurls)")
    g2.add_argument("--gobuster", action="store_true", help="Run Gobuster directory/DNS brute-force (requires gobuster)")
    g2.add_argument("--gobuster-wordlist", help="Wordlist for Gobuster")
    g2.add_argument("--feroxbuster", action="store_true", help="Run Feroxbuster recursive content discovery (requires feroxbuster)")
    g2.add_argument("--masscan", action="store_true", help="Run Masscan ultra-fast port scanner (requires masscan)")
    g2.add_argument("--masscan-ports", default="1-65535", help="Port spec for Masscan (default: 1-65535)")
    g2.add_argument("--masscan-rate", type=int, default=1000, help="Masscan packets per second (default: 1000)")
    g2.add_argument("--rustscan", action="store_true", help="Run RustScan fast port scanner (requires rustscan)")
    g2.add_argument("--hakrawler", action="store_true", help="Run Hakrawler web crawler (requires hakrawler)")
    g2.add_argument("--arjun", action="store_true", help="Run Arjun HTTP parameter discovery (requires arjun)")
    g2.add_argument("--paramspider", action="store_true", help="Run ParamSpider parameter mining (requires paramspider)")
    g2.add_argument("--dirsearch", action="store_true", help="Run Dirsearch web path scanner (requires dirsearch)")
    g2.add_argument("--recon-arsenal", action="store_true", help="Run full Recon Arsenal (all 15 advanced tools) on target")
