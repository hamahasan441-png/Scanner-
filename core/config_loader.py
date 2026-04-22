#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v11.0 — Config File Loader
============================================

Supports ``atomic.yaml`` and ``atomic.toml`` configuration files alongside
CLI flags, so CI pipelines and repeat scans don't require long command lines.

Load priority (highest → lowest):
  1. CLI arguments
  2. ``--config`` path
  3. ``atomic.yaml`` / ``atomic.toml`` in current working directory
  4. ``~/.config/atomic/config.yaml``
  5. Built-in defaults

Usage::

    # Use defaults from atomic.yaml in CWD
    python main.py -t https://target.com

    # Explicit config file
    python main.py --config my_scan.yaml

    # Generate a starter config
    python main.py --gen-config atomic.yaml
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_NAMES = ["atomic.yaml", "atomic.yml", "atomic.toml"]
USER_CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".config", "atomic")

# ---------------------------------------------------------------------------
# Default config skeleton
# ---------------------------------------------------------------------------
DEFAULT_CONFIG: Dict[str, Any] = {
    # --- Scan settings ---
    "depth": 3,
    "threads": 50,
    "timeout": 15,
    "delay": 0.1,
    "evasion": "none",
    "waf_bypass": False,
    "verbose": False,
    "quiet": False,
    # --- Module toggles ---
    "modules": {
        "sqli": False,
        "xss": False,
        "lfi": False,
        "cmdi": False,
        "ssrf": False,
        "ssti": False,
        "xxe": False,
        "idor": False,
        "nosql": False,
        "cors": False,
        "jwt": False,
        "upload": False,
        "open_redirect": False,
        "crlf": False,
        "hpp": False,
        "graphql": False,
        "proto_pollution": False,
        "race_condition": False,
        "websocket": False,
        "deserialization": False,
        "cloud_scan": False,
        "osint": False,
        "fuzzer": False,
        "recon": False,
        "discovery": False,
    },
    # --- Exploitation ---
    "shell": False,
    "dump": False,
    "os_shell": False,
    "brute": False,
    "exploit_chain": False,
    "auto_exploit": False,
    # --- Evasion ---
    "tor": False,
    "proxy": None,
    "rotate_proxy": False,
    "rotate_ua": False,
    # --- Output ---
    "report_format": "html",
    "output_dir": None,
    # --- Notifications ---
    "notify_webhook": None,
    "notify_format": "generic",
    # --- CI/CD ---
    "ci_mode": False,
    "fail_on": None,
    # --- Async ---
    "async_mode": False,
    # --- AI ---
    "local_llm": False,
    "ai_plan": False,
    "ai_plan_auto": False,
    # --- Watch ---
    "watch": False,
    "watch_interval": 300,
    # --- Batch ---
    "batch_parallel": 1,
    # --- Scheduling ---
    "schedule": None,
    "schedule_cron": None,
    "schedule_name": None,
}

STARTER_YAML_TEMPLATE = """\
# ATOMIC Framework v11.0 — Configuration File
# Docs: https://github.com/hamahasan441-png/Scanner-
#
# CLI flags override values defined here.

# ── Scan settings ──────────────────────────────────────────────────────
depth: 3          # crawl depth (1-10)
threads: 50       # concurrent threads
timeout: 15       # request timeout in seconds
delay: 0.1        # delay between requests (seconds)
evasion: none     # evasion level: none | low | medium | high | insane | stealth
waf_bypass: false
verbose: false
quiet: false

# ── Module toggles ─────────────────────────────────────────────────────
modules:
  sqli: false
  xss: false
  lfi: false
  cmdi: false
  ssrf: false
  ssti: false
  xxe: false
  idor: false
  nosql: false
  cors: true        # always-on recommended
  jwt: false
  upload: false
  open_redirect: false
  crlf: false
  hpp: false
  graphql: false
  proto_pollution: false
  race_condition: false
  websocket: false
  deserialization: false
  cloud_scan: false
  osint: false
  fuzzer: false
  recon: false
  discovery: false

# ── Exploitation ───────────────────────────────────────────────────────
shell: false
dump: false
os_shell: false
brute: false
exploit_chain: false
auto_exploit: false

# ── Output ────────────────────────────────────────────────────────────
report_format: html   # html | json | csv | txt | pdf | xml | sarif | all
output_dir: null      # defaults to reports/

# ── Notifications ─────────────────────────────────────────────────────
notify_webhook: null
notify_format: generic   # generic | slack | discord | teams

# ── CI/CD ─────────────────────────────────────────────────────────────
ci_mode: false
fail_on: null    # CRITICAL | HIGH | MEDIUM | LOW

# ── Async mode ────────────────────────────────────────────────────────
async_mode: false   # use httpx async engine

# ── AI features ───────────────────────────────────────────────────────
local_llm: false
ai_plan: false
ai_plan_auto: false

# ── Watch mode ────────────────────────────────────────────────────────
watch: false
watch_interval: 300   # seconds between polls

# ── Batch scanning ────────────────────────────────────────────────────
batch_parallel: 1   # number of parallel workers for -f/--urls
"""


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------


def _load_yaml(path: str) -> Dict:
    try:
        import yaml

        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return data
    except ImportError:
        logger.warning("PyYAML not installed — cannot load %s", path)
        return {}
    except Exception as exc:
        logger.warning("Failed to load YAML config %s: %s", path, exc)
        return {}


def _load_toml(path: str) -> Dict:
    try:
        try:
            import tomllib  # Python 3.11+
        except ImportError:
            import tomli as tomllib  # type: ignore[no-redef]
        with open(path, "rb") as fh:
            return tomllib.load(fh)
    except ImportError:
        logger.debug("tomllib/tomli not available — TOML config unsupported")
        return {}
    except Exception as exc:
        logger.warning("Failed to load TOML config %s: %s", path, exc)
        return {}


def _deep_merge(base: Dict, override: Dict) -> Dict:
    """Merge *override* into *base* (deep for nested dicts)."""
    result = dict(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def find_config_file(explicit_path: Optional[str] = None) -> Optional[str]:
    """Find the first available config file.

    Search order:
      1. *explicit_path* (from ``--config``)
      2. CWD defaults (atomic.yaml, atomic.yml, atomic.toml)
      3. User config dir (~/.config/atomic/config.yaml)
    """
    if explicit_path:
        if os.path.isfile(explicit_path):
            return explicit_path
        logger.warning("Config file not found: %s", explicit_path)
        return None

    # CWD defaults
    for name in DEFAULT_CONFIG_NAMES:
        p = os.path.join(os.getcwd(), name)
        if os.path.isfile(p):
            return p

    # User config
    for name in DEFAULT_CONFIG_NAMES:
        p = os.path.join(USER_CONFIG_DIR, name)
        if os.path.isfile(p):
            return p

    return None


def load_config(path: Optional[str] = None) -> Dict:
    """Load config from *path* (or auto-discover) and merge with defaults.

    Returns a flat config dict ready to be passed to ``AtomicEngine``.
    """
    cfg: Dict = {}

    if not path:
        path = find_config_file()

    if path:
        if path.endswith(".toml"):
            raw = _load_toml(path)
        else:
            raw = _load_yaml(path)

        if raw:
            cfg = raw
            logger.info("Loaded config from %s", path)

    return _deep_merge(DEFAULT_CONFIG, cfg)


def apply_to_argparse_namespace(cfg: Dict, namespace) -> None:
    """Apply config-file values to an ``argparse.Namespace``.

    CLI flags take precedence — only fills in values that are still at their
    default (None / False / 0).
    """
    for key, value in cfg.items():
        if key == "modules":
            continue  # handled separately
        attr = key.replace("-", "_")
        if not hasattr(namespace, attr):
            continue
        current = getattr(namespace, attr)
        # Only override if the CLI value is still at its "unset" default
        if current is None or current is False or current == 0:
            setattr(namespace, attr, value)

    # Modules sub-section
    modules = cfg.get("modules", {})
    for mod, enabled in modules.items():
        attr = mod.replace("-", "_")
        if hasattr(namespace, attr) and not getattr(namespace, attr, False):
            setattr(namespace, attr, enabled)


def generate_starter_config(path: str):
    """Write a starter YAML config to *path*."""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(STARTER_YAML_TEMPLATE)
    print(f"Starter config written to: {path}")
