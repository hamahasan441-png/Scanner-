#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - CLI Commands: Update & Config
"""
import sys
from config import Colors
from core.cli.helpers import print_update_status, maybe_auto_update, startup_update_notice


def handle_update_commands(args):
    """Handle --update, --check-update, early exit. Returns True if handled."""
    if getattr(args, "update", False) or getattr(args, "check_update", False):
        from core.updater import check_for_update, perform_update

        if args.update:
            print(f"{Colors.info('Updating ATOMIC Framework…')}")
            status = perform_update(force=getattr(args, "force", False))
        else:
            print(f"{Colors.info('Checking for updates…')}")
            status = check_for_update()
        print_update_status(status, did_update=bool(args.update))
        sys.exit(1 if status.error else 0)

    return False


def handle_auto_update(args, config):
    """Handle auto-update on startup (opt-in)."""
    from config import Config
    if getattr(args, "auto_update", False) or getattr(Config, "AUTO_UPDATE", False):
        maybe_auto_update(quiet=getattr(args, "quiet", False))
    elif (
        not getattr(args, "quiet", False)
        and not getattr(args, "no_update_check", False)
        and getattr(Config, "UPDATE_CHECK_ENABLED", True)
    ):
        startup_update_notice()


def handle_config_commands(args):
    """Handle --gen-config early exit. Returns True if handled."""
    if getattr(args, "gen_config", None):
        from core.config_loader import generate_starter_config
        generate_starter_config(args.gen_config)
        return True
    return False


def load_config_file(args):
    """Load config file and apply to args namespace. Returns cfg_path or None."""
    try:
        from core.config_loader import find_config_file, load_config, apply_to_argparse_namespace
        cfg_path = find_config_file(getattr(args, "config", None))
        if cfg_path:
            file_cfg = load_config(cfg_path)
            apply_to_argparse_namespace(file_cfg, args)
            if not getattr(args, "quiet", False):
                print(f"{Colors.info(f'Loaded config: {cfg_path}')}")
            return cfg_path
    except FileNotFoundError as exc:
        print(f"{Colors.error(f'Config file not found: {exc}')}")
        sys.exit(1)
    except Exception as exc:
        print(f"{Colors.warning(f'Config load failed ({type(exc).__name__}): {exc} — continuing with CLI args only')}")
    return None
