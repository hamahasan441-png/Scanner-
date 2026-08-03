#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Offensive-action governance
================================================

A small, dependency-free governance layer for the framework's *offensive*
capabilities (auto-exploitation, shell upload, OS-command execution,
post-exploitation). It provides two things:

1. **An opt-in authorization gate** — when enforcement is enabled, offensive
   actions are refused unless the operator has explicitly asserted
   authorization for the engagement (``--authorized`` / ``config["authorized"]``).
2. **A tamper-evident-ish audit trail** — every offensive action (allowed or
   refused) is appended as a JSON line to an audit log, so an engagement can
   always answer "what did the tool attempt, against what, and when".

Design goals
------------
* **Default-permissive / non-breaking.** With no environment configuration the
  gate returns *allowed* for everything, so existing behaviour and the test
  suite are unchanged. Enforcement is strictly opt-in via
  ``ATOMIC_REQUIRE_AUTHORIZATION``.
* **Fail-open on audit, fail-closed on authorization.** Audit-log I/O never
  raises into the scan path (a missing disk must not abort a scan), but when
  enforcement *is* enabled an unauthorized action is refused.
* **stdlib only** — safe to import from anywhere in the engine.

Environment
-----------
``ATOMIC_REQUIRE_AUTHORIZATION``
    Truthy ("1", "true", "yes", "on") to require explicit authorization before
    any offensive action runs. Default: disabled (permissive).
``ATOMIC_AUDIT_LOG``
    Path to the audit log. Default: ``~/.atomic/audit.log``.
``ATOMIC_AUDIT_DISABLED``
    Truthy to disable audit logging entirely.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

_TRUTHY = {"1", "true", "yes", "on", "y"}


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in _TRUTHY


def is_enforced() -> bool:
    """Return True when explicit authorization is required for offensive actions."""
    return _env_truthy("ATOMIC_REQUIRE_AUTHORIZATION")


def _audit_path() -> Path:
    raw = os.environ.get("ATOMIC_AUDIT_LOG", "").strip()
    if raw:
        return Path(raw).expanduser()
    return Path(os.environ.get("ATOMIC_HOME", str(Path.home() / ".atomic"))).expanduser() / "audit.log"


def check_authorization(config: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
    """Decide whether an offensive action may proceed.

    Returns ``(allowed, reason)``. When enforcement is disabled this always
    allows (preserving default behaviour). When enforcement is enabled, the
    action is allowed only if ``config["authorized"]`` is truthy.
    """
    if not is_enforced():
        return True, "authorization enforcement disabled (default)"

    authorized = bool((config or {}).get("authorized"))
    if authorized:
        return True, "operator asserted authorization (--authorized)"
    return False, (
        "offensive action refused: ATOMIC_REQUIRE_AUTHORIZATION is set but the "
        "operator did not assert authorization (pass --authorized only for "
        "systems you are explicitly permitted to test)"
    )


def audit_offensive_action(
    action: str,
    target: Optional[str],
    details: Optional[Dict[str, Any]] = None,
    allowed: bool = True,
) -> None:
    """Append a structured JSON record of an offensive action to the audit log.

    Best-effort: never raises into the caller. A failure to write the audit log
    is logged at DEBUG rather than aborting the scan.
    """
    if _env_truthy("ATOMIC_AUDIT_DISABLED"):
        return

    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "target": target,
        "allowed": allowed,
        "enforced": is_enforced(),
        "pid": os.getpid(),
        "details": details or {},
    }
    try:
        path = _audit_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")
    except Exception as exc:  # pragma: no cover - audit must never break a scan
        logger.debug("Failed to write offensive-action audit record: %s", exc, exc_info=True)
