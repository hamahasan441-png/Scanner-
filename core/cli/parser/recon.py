#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - CLI Parser: Reconnaissance & Discovery
"""
import argparse


def add_recon_arguments(parser: argparse.ArgumentParser):
    """Add recon and discovery arguments."""
    g = parser.add_argument_group("Reconnaissance")
    g.add_argument("--recon", action="store_true", help="Enable reconnaissance")
    g.add_argument("--subdomains", action="store_true", help="Enumerate subdomains")
    g.add_argument("--ports", help="Port scan (e.g., 80,443,8080 or 1-1000)")
    g.add_argument("--tech-detect", action="store_true", help="Detect technologies")
    g.add_argument("--dir-brute", action="store_true", help="Directory brute force")
    g.add_argument("--discovery", action="store_true", help="Enable target discovery & enumeration (robots.txt, sitemap, smart analysis)")
    g.add_argument("--net-exploit", action="store_true", help="Enable network exploit scanning (runs after port scan)")
    g.add_argument("--tech-exploit", action="store_true", help="Enable technology exploit scanning")
    g.add_argument("--scapy", action="store_true", help="Enable Scapy packet-level scanning (SYN, UDP, OS fingerprint)")
    g.add_argument("--scapy-crawl", action="store_true", help="Enable Scapy network crawl")
    g.add_argument("--stealth-scan", action="store_true", help="Enable stealthy SYN port scanning via Scapy")
    g.add_argument("--arp-discovery", action="store_true", help="Enable ARP-based local network host discovery")
    g.add_argument("--dns-recon", action="store_true", help="Enable DNS recon (zone transfer + subdomain brute-force)")
    g.add_argument("--traceroute", action="store_true", help="Enable traceroute during Scapy crawl")
    g.add_argument("--subnet", help="Subnet for ARP discovery (e.g., 192.168.1.0/24)")
    g.add_argument("--scapy-vuln-scan", action="store_true", help="Enable Scapy packet-level vulnerability scanning")
    g.add_argument("--scapy-attack-chain", action="store_true", help="Enable Scapy network attack chain templates")
    g.add_argument("--shield-detect", action="store_true", help="Enable CDN/WAF detection (Shield Detector)")
    g.add_argument("--real-ip", action="store_true", help="Enable real IP / origin server discovery (behind CDN)")
    g.add_argument("--passive-recon", action="store_true", help="Enable passive reconnaissance fan-out (Shodan, Censys, etc)")
    g.add_argument("--enrich", action="store_true", help="Enable intelligence enrichment (Phase 10)")
    g.add_argument("--chain-detect", action="store_true", help="Enable exploit chain detection (Phase 9)")
    g.add_argument("--exploit-search", action="store_true", help="Enable 7-source exploit reference search (Phase 9B)")
    g.add_argument("--agent-scan", action="store_true", help="Enable autonomous goal-driven OODA agent scanning")
    g.add_argument("--attack-map", action="store_true", help="Enable Phase 11 exploit-aware attack map generation")
    g.add_argument("--show-plan", action="store_true", help="Display visual scan execution plan before scanning")
