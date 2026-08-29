#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - CLI Helpers
Small utility functions previously embedded in main.py
"""
import os
import sys
import warnings
from config import Colors

# Suppress warnings globally (kept from original main.py)
warnings.filterwarnings("ignore")


def parse_csv(value):
    """Parse comma-separated CLI values into a trimmed list."""
    if not value:
        return []
    return [x.strip() for x in value.split(",") if x.strip()]


def print_update_status(status, did_update=False):
    """Human-readable rendering of an UpdateStatus."""
    if status.error:
        print(f"{Colors.error('Update error:')} {status.error}")
        return
    if did_update:
        print(f"{Colors.success('✓')} {status.detail or 'Update complete.'}")
        return
    if status.available:
        print(f"{Colors.warning('⇧ Update available')} — current v{status.current}, "
              f"latest {status.latest} (via {status.method}).")
        print(f"  Run {Colors.BOLD}--update{Colors.RESET} to upgrade.")
    else:
        print(f"{Colors.success('✓ Up to date')} (v{status.current}).")


def maybe_auto_update(quiet=False):
    """Apply an available update on startup, then re-exec with new code."""
    if os.environ.get("ATOMIC_UPDATED") == "1":
        return
    try:
        from core.updater import check_for_update, perform_update

        status = check_for_update()
        if not status.available:
            return
        if not quiet:
            print(f"{Colors.info('Auto-update: applying latest version…')}")
        result = perform_update()
        if result.error:
            if not quiet:
                print(f"{Colors.warning('Auto-update skipped:')} {result.error}")
            return
        if not quiet:
            print(f"{Colors.success('✓')} {result.detail}")
        os.environ["ATOMIC_UPDATED"] = "1"
        os.execv(sys.executable, [sys.executable] + sys.argv)
    except Exception as exc:
        if not quiet:
            print(f"{Colors.warning(f'Auto-update failed ({type(exc).__name__}): {exc}')}")


def startup_update_notice():
    """One-line, throttled, fail-silent 'update available' notice."""
    try:
        from core.updater import check_throttled

        status = check_throttled()
        if status.available:
            print(f"{Colors.warning('⇧ A new ATOMIC version is available')} "
                  f"(latest {status.latest}). Run {Colors.BOLD}--update{Colors.RESET} to upgrade.")
    except Exception:
        pass


def maybe_normalize_url(url: str, field_name: str = "url") -> str:
    """Normalize URL via atomic.urlnorm if available, else return as-is."""
    try:
        from atomic.urlnorm import normalize as _normalize
        return _normalize(url)
    except Exception:
        return url
