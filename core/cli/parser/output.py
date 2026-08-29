#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - CLI Parser: Output & Reporting
"""
import argparse


def add_output_arguments(parser: argparse.ArgumentParser):
    """Add output, reporting, and shell manager arguments."""
    g = parser.add_argument_group("Output / Reporting")
    g.add_argument("--report", help="Generate report for scan ID")
    g.add_argument("--format", default="html", choices=["html", "json", "csv", "txt", "pdf", "xml", "sarif", "all"], help="Report format (default: html)")
    g.add_argument("--list-scans", action="store_true", help="List all scans")
    g.add_argument("--output", "-o", help="Output directory for reports")
    g.add_argument("--shell-manager", action="store_true", help="Launch interactive shell manager")
    g.add_argument("--shell-id", help="Shell ID to interact with")
    g.add_argument("--shell-cmd", help="Command to execute on shell")
    g.add_argument("--show-learned", action="store_true", help="Show learned payloads from AI engine")
