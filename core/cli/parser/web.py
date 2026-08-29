#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - CLI Parser: Web / Burp Tools
"""
import argparse


def add_web_arguments(parser: argparse.ArgumentParser):
    """Add web dashboard and Burp Suite tool arguments."""
    g = parser.add_argument_group("Web Dashboard")
    g.add_argument("--web", action="store_true", help="Launch Flask web dashboard")
    g.add_argument("--web-host", default="127.0.0.1", help="Web dashboard bind address (default: 127.0.0.1, loopback only). Use 0.0.0.0 for all interfaces")
    g.add_argument("--web-public", action="store_true", help="Bind web dashboard to 0.0.0.0 (all interfaces)")
    g.add_argument("--web-port", type=int, default=5000, help="Web dashboard port (default: 5000)")

    g2 = parser.add_argument_group("Burp Suite Tools")
    g2.add_argument("--proxy-server", action="store_true", help="Launch intercepting proxy server")
    g2.add_argument("--proxy-port", type=int, default=8080, help="Proxy server port (default: 8080)")
    g2.add_argument("--proxy-intercept", action="store_true", help="Enable request interception on proxy")
    g2.add_argument("--repeater", action="store_true", help="Launch repeater (replay raw HTTP request from stdin or file)")
    g2.add_argument("--repeater-file", help="File containing raw HTTP request for repeater")
    g2.add_argument("--intruder", action="store_true", help="Launch intruder attack mode")
    g2.add_argument("--intruder-url", help="URL for intruder attack")
    g2.add_argument("--intruder-payloads", help="File containing payloads (one per line)")
    g2.add_argument("--decode", metavar="DATA", help="Decode data (auto-detect encoding)")
    g2.add_argument("--encode", metavar="DATA", help="Encode data")
    g2.add_argument("--encode-type", default="url", help="Encode type (url, base64, html, hex, etc)")
    g2.add_argument("--hash-type", help="Hash data with specified algorithm")
    g2.add_argument("--sequencer", metavar="FILE", help="Analyze token randomness from file")
    g2.add_argument("--compare", nargs=2, metavar="FILE", help="Compare two response files")
