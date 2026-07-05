#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - LLM Configuration Wizard & Persistence
=========================================================

Stores cloud-LLM provider, default model, API keys, base URLs and the
multi-model routing profile in a JSON file under
``ATOMIC_HOME/llm_config.json`` (typically ``~/.atomic/llm_config.json``).

API keys can also be supplied via environment variables; the file is a
convenience for users who don't want to export variables on every run.
Environment variables take precedence over the file at lookup time, so
ad-hoc overrides like ``ANTHROPIC_API_KEY=... python main.py ...`` work
as expected.

Run the interactive wizard with::

    python main.py --llm-config

Inspired by Decepticon's ``decepticon config`` flow — only the
configuration-flow concept was borrowed.
"""

import json
import os
import stat

from config import Config, Colors


CONFIG_PATH = os.path.join(Config.ATOMIC_HOME, "llm_config.json")


SUPPORTED_PROVIDERS = [
    "anthropic",
    "openai",
    "gemini",
    "groq",
    "openrouter",
    "ollama",
    "mistral",
    "deepseek",
    "together_ai",
    "xai",
    "azure",
    "bedrock",
    "dashscope",
]

SUPPORTED_PROFILES = ["eco", "max", "mixed", "test", "local", "qwen"]


# Env var names checked when resolving an API key. Match the table in
# ``core.cloud_llm`` so a single source of truth wins.
ENV_KEYS = {
    "anthropic": ("ANTHROPIC_API_KEY",),
    "openai": ("OPENAI_API_KEY",),
    "gemini": ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
    "groq": ("GROQ_API_KEY",),
    "openrouter": ("OPENROUTER_API_KEY",),
    "mistral": ("MISTRAL_API_KEY",),
    "deepseek": ("DEEPSEEK_API_KEY",),
    "together_ai": ("TOGETHER_API_KEY", "TOGETHER_AI_API_KEY"),
    "xai": ("XAI_API_KEY",),
    "azure": ("AZURE_API_KEY",),
    "bedrock": ("AWS_ACCESS_KEY_ID",),
    "dashscope": ("DASHSCOPE_API_KEY", "QWEN_API_KEY"),
}


# ---------------------------------------------------------------------
# Load / save
# ---------------------------------------------------------------------


def load_config():
    """Return the persisted LLM config dict, or ``{}`` if none."""
    if not os.path.isfile(CONFIG_PATH):
        return {}
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh) or {}
    except (OSError, json.JSONDecodeError):
        return {}


def save_config(cfg):
    """Persist LLM config to ``CONFIG_PATH`` with 0600 perms."""
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2, sort_keys=True)
    os.replace(tmp, CONFIG_PATH)
    try:
        os.chmod(CONFIG_PATH, stat.S_IRUSR | stat.S_IWUSR)  # 0600 — keys live here
    except OSError:
        pass


# ---------------------------------------------------------------------
# Resolution helpers
# ---------------------------------------------------------------------


def get_api_keys(cfg=None):
    """Resolve API keys from config file + environment variables.

    Environment variables take precedence so users can override the
    file on a single run.
    """
    cfg = cfg if cfg is not None else load_config()
    out = dict(cfg.get("api_keys", {}) or {})
    for provider, var_names in ENV_KEYS.items():
        for v in var_names:
            val = os.environ.get(v)
            if val:
                out[provider] = val
                break
    return out


def get_base_urls(cfg=None):
    cfg = cfg if cfg is not None else load_config()
    return dict(cfg.get("base_urls", {}) or {})


def get_default_provider(cfg=None):
    cfg = cfg if cfg is not None else load_config()
    return cfg.get("provider")


def get_default_model(cfg=None):
    cfg = cfg if cfg is not None else load_config()
    return cfg.get("model")


def get_default_profile(cfg=None):
    cfg = cfg if cfg is not None else load_config()
    return cfg.get("profile")


# ---------------------------------------------------------------------
# Status / diagnostics
# ---------------------------------------------------------------------


def print_status():
    """Print a summary of the persisted LLM configuration."""
    cfg = load_config()
    print(f"{Colors.info('ATOMIC LLM Configuration')}")
    print(f"  Config file: {CONFIG_PATH}")
    if not cfg:
        print(f"  {Colors.warning('(no config — run `python main.py --llm-config`)')}")
        return

    print(f"  Profile     : {cfg.get('profile', '(unset)')}")
    print(f"  Provider    : {cfg.get('provider', '(unset)')}")
    print(f"  Model       : {cfg.get('model', '(default)')}")

    keys = get_api_keys(cfg)
    print("  API keys    :")
    for p in SUPPORTED_PROVIDERS:
        v = keys.get(p, "")
        if v:
            # Never log any portion of the key — even the tail can leak in
            # logs, screen recordings, or CI artefacts. Just confirm presence.
            print(f"    {p:<14s}: (set)")
        else:
            env_hint = ENV_KEYS.get(p, ())
            hint = f" (or set {env_hint[0]})" if env_hint else ""
            print(f"    {p:<14s}: (unset){hint}")


# ---------------------------------------------------------------------
# Interactive wizard
# ---------------------------------------------------------------------


def run_wizard():
    """Interactive setup wizard. Re-runnable; preserves existing values."""
    cfg = load_config()
    print(f"{Colors.info('ATOMIC LLM Configuration Wizard')}")
    print(f"  Config file: {CONFIG_PATH}")
    print()

    # Routing profile -------------------------------------------------
    current_profile = cfg.get("profile", "mixed")
    print(f"Available profiles: {', '.join(SUPPORTED_PROFILES)}")
    profile = (
        input(f"Routing profile [{current_profile}]: ").strip() or current_profile
    )
    if profile not in SUPPORTED_PROFILES:
        print(
            f"{Colors.warning(f'Unknown profile {profile} — keeping {current_profile}')}"
        )
        profile = current_profile
    cfg["profile"] = profile

    # Default provider / model ---------------------------------------
    current_provider = cfg.get("provider", "anthropic")
    print(f"\nAvailable providers: {', '.join(SUPPORTED_PROVIDERS)}")
    provider = (
        input(f"Default provider [{current_provider}]: ").strip().lower()
        or current_provider
    )
    if provider not in SUPPORTED_PROVIDERS:
        print(
            f"{Colors.warning(f'Unknown provider {provider} — keeping {current_provider}')}"
        )
        provider = current_provider
    cfg["provider"] = provider

    current_model = cfg.get("model") or ""
    model = input(
        f"Default model (blank = use provider default) [{current_model}]: "
    ).strip() or current_model
    if model:
        cfg["model"] = model
    else:
        cfg.pop("model", None)

    # API keys --------------------------------------------------------
    api_keys = dict(cfg.get("api_keys", {}) or {})
    print("\nEnter API keys (blank to keep existing, '-' to clear).")
    for p in SUPPORTED_PROVIDERS:
        if p == "ollama":
            continue  # local — no key
        existing = api_keys.get(p, "")
        # Never echo any portion of the key in the prompt — show only
        # whether one is currently set.
        status = "(set)" if existing else "(unset)"
        val = input(f"  {p:<14s} [{status}]: ").strip()
        if val == "-":
            api_keys.pop(p, None)
        elif val:
            api_keys[p] = val
    cfg["api_keys"] = api_keys

    # Optional custom base URLs --------------------------------------
    print("\nOptional custom base URLs (blank to skip / keep, '-' to clear).")
    base_urls = dict(cfg.get("base_urls", {}) or {})
    for p in ("ollama", "openrouter", "azure"):
        existing = base_urls.get(p, "")
        val = input(f"  {p:<14s} URL [{existing}]: ").strip()
        if val == "-":
            base_urls.pop(p, None)
        elif val:
            base_urls[p] = val
    cfg["base_urls"] = base_urls

    save_config(cfg)
    print(f"\n{Colors.success(f'Saved {CONFIG_PATH} (mode 0600)')}")
    return cfg


if __name__ == "__main__":
    run_wizard()
