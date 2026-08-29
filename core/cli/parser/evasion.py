#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - CLI Parser: Evasion Options
"""
import argparse
from config import Config


def add_evasion_arguments(parser: argparse.ArgumentParser):
    """Add evasion and WAF bypass arguments."""
    g = parser.add_argument_group("Evasion")
    g.add_argument("-e", "--evasion", choices=Config.EVASION_LEVELS, default="none", help="Evasion level (default: none)")
    g.add_argument("--waf-bypass", action="store_true", help="Enable WAF bypass techniques")
    g.add_argument(
        "--full-bypass", action="store_true",
        help="Activate universal BypassOrchestrator: adaptive WAF evasion ladder with per-host learning ledger"
    )
    g.add_argument("--tor", action="store_true", help="Route through Tor network")
    g.add_argument("--proxy", help="Use proxy (format: http://host:port)")
    g.add_argument("--rotate-proxy", action="store_true", help="Rotate proxies automatically")
    g.add_argument("--rotate-ua", action="store_true", help="Rotate User-Agent automatically")
    g.add_argument(
        "--insecure-tls", action="store_true",
        help="Disable TLS certificate verification. USE WITH CAUTION — needed only for self-signed certs."
    )
