#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - CLI Commands: LLM & Model
"""
import sys
from config import Colors


def handle_llm_commands(args):
    """Handle LLM config, status, download-model. Returns True if handled."""

    if getattr(args, "llm_config", False):
        try:
            from core.llm_config import run_wizard
            run_wizard()
        except Exception as exc:
            print(f"{Colors.error(f'LLM config error: {exc}')}")
        return True

    if getattr(args, "llm_status", False):
        try:
            from core.llm_config import print_status, load_config
            from core.llm_router import DEFAULT_PROFILES, TASKS
            print_status()
            cfg = load_config()
            profile = cfg.get("profile")
            if profile and profile in DEFAULT_PROFILES:
                print(f"\n{Colors.info(f'Routing profile: {profile}')}")
                for task in TASKS:
                    provider, model = DEFAULT_PROFILES[profile][task]
                    print(f"  {task:<10s} -> {provider}/{model}")
        except Exception as exc:
            print(f"{Colors.error(f'LLM status error: {exc}')}")
        return True

    if getattr(args, "download_model", False):
        try:
            from core.local_llm import download_model, LocalLLM
            download_model()
            if not LocalLLM.is_available():
                LocalLLM.install_backend()
        except Exception as exc:
            print(f"{Colors.error(f'Model download error: {exc}')}")
        return True

    return False
