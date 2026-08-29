#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Enhanced Main Entry Point
Refactored from 2521-line monolith to modular CLI architecture.

New structure:
- core/cli/parser/        → Argument groups (target, scan, modules, etc.)
- core/cli/commands/      → Command handlers (tools, recon, web, scan, etc.)
- core/cli/helpers.py     → Shared helpers (_parse_csv, update notices)
- core/cli/app.py         → Main dispatcher (run_cli)

This file is now ~80 lines vs 2521 lines previously, with:
- Faster startup (lazy imports)
- Better maintainability (single responsibility per module)
- Easier testing (each command independently testable)
- Clear separation of concerns

For legacy reference, see main_legacy.py (original 2521-line version).
For authorized testing only.
"""
import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Delegate to new modular CLI
from core.cli.app import run_cli

def main():
    """Enhanced main entry point — delegates to modular CLI."""
    run_cli()

if __name__ == "__main__":
    main()
