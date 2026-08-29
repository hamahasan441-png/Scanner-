#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - CLI Application
New modular main dispatcher that keeps main.py small.
This replaces the monolithic 2521-line main.py with a clean router.

Usage:
    from core.cli.app import run_cli
    run_cli()

Or via python -m core.cli
"""
import sys
import os
import time

# Add repo root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from config import Config, Colors
from core.cli.parser import create_parser
from core.cli.helpers import parse_csv, maybe_normalize_url
from core.cli.commands.tools import handle_tools_runtime, handle_tools_downloader
from core.cli.commands.update import handle_update_commands, handle_auto_update, handle_config_commands, load_config_file
from core.cli.commands.web import handle_web_commands
from core.cli.commands.recon import handle_recon_tools
from core.cli.commands.report import handle_report_commands
from core.cli.commands.llm import handle_llm_commands
from core.cli.commands.scan import handle_scan
from core.cli.commands.benchmark import handle_benchmark
from core.cli.commands.calibrate import handle_calibrate


def _get_print_banner():
    """Get print_banner, respecting patch from main module for legacy tests."""
    try:
        import main as _main
        import unittest.mock as _mock
        if hasattr(_main, "print_banner") and isinstance(_main.print_banner, _mock.MagicMock):
            return _main.print_banner
    except Exception:
        pass
    try:
        from core.banner import print_banner as _real
        return _real
    except ImportError:
        return lambda: None


def _normalize_targets(args):
    """Normalize target URLs via atomic.urlnorm if available."""
    try:
        from atomic.urlnorm import normalize as _normalize_target
    except Exception:
        _normalize_target = None

    def _maybe_normalize(value, field):
        if not value or _normalize_target is None:
            return value
        try:
            normalized = _normalize_target(value)
            if normalized != value and not getattr(args, "quiet", False):
                print(f"{Colors.info(f'Normalized {field} {value!r} → {normalized}')}")
            return normalized
        except ValueError as exc:
            print(f"{Colors.error(str(exc))}", file=sys.stderr)
            sys.exit(2)

    if getattr(args, "target", None):
        args.target = _maybe_normalize(args.target, "target")
    if getattr(args, "url", None):
        args.url = _maybe_normalize(args.url, "url")


def run_cli(argv=None):
    """Entry point for CLI: parse args, dispatch to handlers, run scan if needed."""
    parser = create_parser()
    args = parser.parse_args(argv)

    # Normalize targets early (accept example.com)
    _normalize_targets(args)

    # --- Early exit commands (no banner, no DB) ---
    # Tools runtime (portable, status, doctor) - independent of web stack
    if handle_tools_runtime(args):
        return

    # Benchmark suite (network-free diagnostic) - independent of web/DB stack
    if handle_benchmark(args):
        return

    # Confidence calibration report (offline diagnostic)
    if handle_calibrate(args):
        return

    # Banner (unless quiet) — supports legacy patching via main.print_banner
    if not getattr(args, "quiet", False):
        _get_print_banner()()

    # Update commands
    if handle_update_commands(args):
        return

    # Auto-update on startup (opt-in)
    # We need config for this, but we can call with args
    try:
        handle_auto_update(args, Config)
    except Exception:
        pass

    # Config file handling
    if handle_config_commands(args):
        return

    # Load config file (lowest priority, CLI overrides)
    load_config_file(args)

    # Distributed worker mode
    if getattr(args, "worker", None):
        try:
            from core.distributed import DistributedWorker
            worker = DistributedWorker(
                redis_url=args.worker,
                worker_id=getattr(args, "worker_id", None)
            )
            worker.run()
        except Exception as exc:
            print(f"{Colors.error(f'Worker error: {exc}')}")
        return

    # OpenAPI spec
    if getattr(args, "api_spec", False):
        try:
            from web.openapi import print_openapi_spec
            print_openapi_spec()
        except ImportError:
            import json
            spec = {
                "openapi": "3.0.0",
                "info": {"title": "ATOMIC Framework REST API", "version": "11.0.0"},
                "paths": {}
            }
            print(json.dumps(spec, indent=2))
        return

    # Tools downloader (check, install)
    if handle_tools_downloader(args):
        return

    # LLM commands
    if handle_llm_commands(args):
        return

    # Web / Burp tools
    if handle_web_commands(args):
        return

    # Recon standalone tools (nmap, nuclei, etc) - handled before main scan
    # Note: handle_recon_tools returns True only if it actually ran a recon tool standalone
    # We want to allow recon tools to be part of scan too, but if --recon-arsenal etc alone, exit
    # For now, if any recon flag and no other scan modules, we exit after recon
    # To avoid double handling, check if only recon tools requested without full scan
    recon_only = any(getattr(args, flag, False) for flag in [
        "nmap", "nuclei", "nikto", "whatweb", "subfinder",
        "amass", "httpx", "katana", "dnsx", "ffuf", "gau", "waybackurls",
        "gobuster", "feroxbuster", "masscan", "rustscan", "hakrawler",
        "arjun", "paramspider", "dirsearch", "recon_arsenal"
    ]) and not getattr(args, "full", False) and not getattr(args, "sqli", False)

    if recon_only and getattr(args, "target", None):
        if handle_recon_tools(args):
            return

    # Report / DB / Shell manager
    if handle_report_commands(args):
        return

    # If no target and no special command, show help and exit
    has_target = getattr(args, "target", None) or getattr(args, "file", None) or getattr(args, "urls", None)
    if not has_target:
        # Check if any scan-related flag was set without target
        if any(getattr(args, flag, False) for flag in ["sqli", "xss", "full", "quick", "standard", "deep"]):
            print(f"{Colors.error('No target specified. Use -t/--target, -f/--file, or --urls')}")
            parser.print_help()
            sys.exit(1)
        # If literally no args at all, exit with error (test expects SystemExit)
        if len(sys.argv) <= 1 or (len(sys.argv) == 2 and "--authorized" in sys.argv):
            # No args or only --authorized without target -> show help and exit
            parser.print_help()
            sys.exit(1)
        # For other cases with no target but some other flag (like --check-deps) already handled earlier,
        # just show help and return
        parser.print_help()
        sys.exit(1)

    # Main scan handling (single, batch, distributed)
    if not handle_scan(args):
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    run_cli()
