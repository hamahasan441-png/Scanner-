#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - CLI Parser: Scan Options
"""
import argparse
from config import Config


def add_scan_arguments(parser: argparse.ArgumentParser):
    """Add scan configuration arguments."""
    g = parser.add_argument_group("Scan Options")
    g.add_argument("-d", "--depth", type=int, default=3, help="Crawl depth (1-10, default: 3)")
    g.add_argument("-T", "--threads", type=int, default=50, help="Number of threads (default: 50)")
    g.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")
    g.add_argument("--delay", type=float, default=0.1, help="Delay between requests (default: 0.1)")
    g.add_argument("--full", action="store_true", help="Enable all modules")
    g.add_argument(
        "--point-to-point", action="store_true",
        help="Ultimate scan: enable every module, recon, exploitation, network scanning, and post-exploitation"
    )
    g.add_argument(
        "--turbo", action="store_true",
        help="Maximum parallelism: parallel baseline capture, concurrent worker dispatch, aggressive threading"
    )
    g.add_argument("--rate-limit", type=float, default=10.0, metavar="RPS",
                   help="Maximum requests per second across all modules (default: 10.0). Set to 0 to disable.")
