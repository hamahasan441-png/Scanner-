#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - CLI Parser: Target Options
"""
import argparse


def add_target_arguments(parser: argparse.ArgumentParser):
    """Add target-related arguments."""
    g = parser.add_argument_group("Target Options")
    g.add_argument("-t", "--target", help="Target URL to scan")
    g.add_argument("-f", "--file", help="File containing list of targets")
    g.add_argument("--urls", help="Comma-separated list of URLs")
    g.add_argument(
        "--authorized", action="store_true",
        help="Confirm you are authorized to test the specified targets"
    )
    g.add_argument(
        "--unsafe-mode", action="store_true",
        help="Per-run operator-tuning lift. Disables noise-control caps for current invocation only. "
             "Requires --authorized; does NOT weaken --authorized, scope policy, or auth gates."
    )
    g.add_argument(
        "--strict-scope", action="store_true",
        help="Enforce strict target scope (do not auto-expand from target host)"
    )
    g.add_argument("--allow-domain", help="Comma-separated allowed domains for strict scope enforcement")
    g.add_argument("--allow-path", help="Comma-separated allowed path prefixes (e.g., /api,/v1)")
    g.add_argument("--exclude-path", help="Comma-separated excluded path prefixes (e.g., /admin,/internal)")
    g.add_argument(
        "--regulated-mission", action="store_true",
        help="Enable regulated mission order (safe baseline -> prioritized scan -> verification/report)"
    )
