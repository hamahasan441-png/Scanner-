#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Audit Logger
Tamper-proof audit trail for all security-relevant operations.

Records:
  - Authentication events (login, logout, failed attempts)
  - Scan lifecycle events (created, started, completed, failed)
  - Exploitation actions
  - Configuration changes
  - Data exports / report generation
  - User management actions

Each entry includes: timestamp, actor, action, target, result, IP, details.
"""

import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

_logger = logging.getLogger(__name__)


# Audit event categories
class AuditCategory:
    AUTH = "auth"
    SCAN = "scan"
    EXPLOIT = "exploit"
    REPORT = "report"
    USER = "user"
    CONFIG = "config"
    SYSTEM = "system"
    SCHEDULE = "schedule"
    COMPLIANCE = "compliance"


# Audit severity levels
class AuditSeverity:
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class AuditEntry:
    """A single audit log entry."""

    entry_id: str = ""
    timestamp: str = ""
    category: str = ""
    severity: str = "info"
    actor: str = ""  # username or 'system'
    action: str = ""  # e.g., 'login', 'scan.create', 'exploit.run'
    target: str = ""  # what was acted upon (scan_id, user, URL)
    result: str = ""  # 'success' | 'failure' | 'denied'
    ip_address: str = ""
    details: dict = field(default_factory=dict)
    checksum: str = ""  # HMAC for tamper detection

    def to_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp,
            "category": self.category,
            "severity": self.severity,
            "actor": self.actor,
            "action": self.action,
            "target": self.target,
            "result": self.result,
            "ip_address": self.ip_address,
            "details": self.details,
            "checksum": self.checksum,
        }


class AuditLogger:
    """Tamper-proof audit logging system."""

    # Sensitive substrings — keys whose value should be redacted before
    # storage.  Matched case-insensitively against keys in ``details``.
    _REDACT_KEY_PATTERNS = (
        "password", "passwd", "pwd",
        "secret", "token", "api_key", "apikey",
        "authorization", "auth", "bearer",
        "cookie", "session", "sessid", "csrf",
        "private_key", "privatekey",
        "credit_card", "card_number", "cvv",
        "ssn",
    )
    _REDACTED = "***REDACTED***"

    @classmethod
    def _resolve_secret(cls, explicit: str) -> tuple:
        """Return (secret, source) for HMAC computation.

        Resolution order:
            1. ``explicit`` argument (test-only path).
            2. ``ATOMIC_AUDIT_SECRET`` environment variable.
            3. ``~/.atomic/audit.key`` — read or created with mode 0600.

        A persisted key is essential: with a fresh per-process random
        key, checksums computed in run 1 cannot be verified in run 2,
        which silently breaks tamper detection.
        """
        if explicit:
            return explicit, "explicit"

        env = os.environ.get("ATOMIC_AUDIT_SECRET", "").strip()
        if env:
            return env, "env"

        # Persist a key under ATOMIC_HOME so checksums survive restarts.
        try:
            from config import Config as _Cfg
            atomic_home = getattr(_Cfg, "ATOMIC_HOME", os.path.expanduser("~/.atomic"))
        except Exception:
            atomic_home = os.path.expanduser("~/.atomic")

        key_path = os.path.join(atomic_home, "audit.key")
        try:
            os.makedirs(atomic_home, exist_ok=True)
            if os.path.exists(key_path):
                with open(key_path, "r") as fh:
                    persisted = fh.read().strip()
                if persisted:
                    return persisted, "file"
            # Generate, persist with restrictive permissions, then return.
            generated = secrets.token_hex(32)
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, generated.encode())
            finally:
                os.close(fd)
            try:
                os.chmod(key_path, 0o600)
            except OSError:
                pass
            return generated, "file_new"
        except OSError as exc:
            _logger.warning(
                "Could not persist audit key (%s) — falling back to a "
                "process-local random key. Tamper detection will NOT "
                "survive restarts. Set ATOMIC_AUDIT_SECRET to fix this.",
                exc,
            )
            return secrets.token_hex(32), "ephemeral"

    @classmethod
    def _redact_details(cls, details: Optional[dict]) -> dict:
        """Return a redacted copy of *details*.

        Recursively walks dicts/lists and replaces values whose key
        matches one of ``_REDACT_KEY_PATTERNS``. Non-mapping values
        (str, int, etc.) are returned untouched.
        """
        if not details:
            return {}

        def _walk(node):
            if isinstance(node, dict):
                clean = {}
                for k, v in node.items():
                    key_lower = str(k).lower()
                    if any(p in key_lower for p in cls._REDACT_KEY_PATTERNS):
                        clean[k] = cls._REDACTED
                    else:
                        clean[k] = _walk(v)
                return clean
            if isinstance(node, list):
                return [_walk(x) for x in node]
            if isinstance(node, tuple):
                return tuple(_walk(x) for x in node)
            return node

        return _walk(details)

    def __init__(self, max_entries: int = 10000, secret: str = ""):
        self._entries: List[AuditEntry] = []
        self._lock = threading.Lock()
        self._max_entries = max_entries
        resolved_secret, secret_source = self._resolve_secret(secret)
        self._secret = resolved_secret
        self._secret_source = secret_source
        if secret_source == "ephemeral":
            _logger.warning(
                "Audit secret is ephemeral — checksums will not survive "
                "restarts. Set ATOMIC_AUDIT_SECRET or ensure ATOMIC_HOME "
                "is writable to enable persistent tamper detection."
            )
        self._counter = 0
        self._callbacks: List = []

    def log(
        self,
        category: str,
        action: str,
        actor: str = "system",
        target: str = "",
        result: str = "success",
        severity: str = AuditSeverity.INFO,
        ip_address: str = "",
        details: Optional[dict] = None,
    ) -> AuditEntry:
        """Record an audit event.

        ``details`` is redacted before storage so secrets/cookies/tokens
        captured in passing don't leak into the audit trail.
        """
        with self._lock:
            self._counter += 1
            entry_id = f"AE-{self._counter:06d}"

        entry = AuditEntry(
            entry_id=entry_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            category=category,
            severity=severity,
            actor=actor,
            action=action,
            target=target,
            result=result,
            ip_address=ip_address,
            details=self._redact_details(details),
        )

        # Compute tamper-detection checksum
        entry.checksum = self._compute_checksum(entry)

        with self._lock:
            self._entries.append(entry)
            if len(self._entries) > self._max_entries:
                self._entries = self._entries[-self._max_entries :]

        # Notify callbacks
        for cb in self._callbacks:
            try:
                cb(entry)
            except Exception as exc:
                _logger.warning("Audit callback %r failed: %s", cb, exc)

        return entry

    def _compute_checksum(self, entry: AuditEntry) -> str:
        """Compute HMAC-SHA256 checksum for tamper detection.

        Uses proper HMAC construction (RFC 2104) instead of naive
        ``hash(secret + data)`` which is vulnerable to length-extension
        attacks.
        """
        data = (
            f"{entry.entry_id}|{entry.timestamp}|{entry.category}"
            f"|{entry.action}|{entry.actor}|{entry.target}|{entry.result}"
        )
        return hmac.new(
            self._secret.encode(),
            data.encode(),
            hashlib.sha256,
        ).hexdigest()[:16]

    def verify_checksum(self, entry: AuditEntry) -> bool:
        """Verify an entry's checksum has not been tampered with."""
        expected = self._compute_checksum(entry)
        return entry.checksum == expected

    def add_callback(self, callback):
        """Register a callback for real-time audit event notifications."""
        self._callbacks.append(callback)

    # --- Query methods ---

    def get_entries(
        self,
        category: Optional[str] = None,
        actor: Optional[str] = None,
        action: Optional[str] = None,
        severity: Optional[str] = None,
        since: Optional[str] = None,
        limit: int = 100,
    ) -> List[dict]:
        """Query audit entries with optional filters."""
        with self._lock:
            entries = list(self._entries)

        if category:
            entries = [e for e in entries if e.category == category]
        if actor:
            entries = [e for e in entries if e.actor == actor]
        if action:
            entries = [e for e in entries if action in e.action]
        if severity:
            entries = [e for e in entries if e.severity == severity]
        if since:
            entries = [e for e in entries if e.timestamp >= since]

        # Most recent first
        entries = entries[-limit:]
        entries.reverse()
        return [e.to_dict() for e in entries]

    def get_stats(self) -> dict:
        """Return audit log statistics."""
        with self._lock:
            entries = list(self._entries)

        categories = {}
        severities = {}
        actors = {}
        results = {}

        for e in entries:
            categories[e.category] = categories.get(e.category, 0) + 1
            severities[e.severity] = severities.get(e.severity, 0) + 1
            actors[e.actor] = actors.get(e.actor, 0) + 1
            results[e.result] = results.get(e.result, 0) + 1

        return {
            "total_entries": len(entries),
            "categories": categories,
            "severities": severities,
            "top_actors": dict(sorted(actors.items(), key=lambda x: -x[1])[:10]),
            "results": results,
        }

    def get_security_events(self, limit: int = 50) -> List[dict]:
        """Return security-relevant events (failed logins, exploit attempts, etc.)."""
        return self.get_entries(
            severity=AuditSeverity.WARNING,
            limit=limit,
        ) + self.get_entries(
            severity=AuditSeverity.CRITICAL,
            limit=limit,
        )

    def export_json(self) -> str:
        """Export all audit entries as JSON."""
        with self._lock:
            entries = list(self._entries)
        return json.dumps(
            [e.to_dict() for e in entries],
            indent=2,
        )

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    # --- Convenience logging methods ---

    def log_auth(self, action: str, actor: str, result: str = "success", ip_address: str = "", **kwargs) -> AuditEntry:
        severity = AuditSeverity.INFO if result == "success" else AuditSeverity.WARNING
        return self.log(
            AuditCategory.AUTH,
            action,
            actor=actor,
            result=result,
            severity=severity,
            ip_address=ip_address,
            details=kwargs,
        )

    def log_scan(
        self, action: str, actor: str = "system", target: str = "", result: str = "success", **kwargs
    ) -> AuditEntry:
        return self.log(AuditCategory.SCAN, action, actor=actor, target=target, result=result, details=kwargs)

    def log_exploit(
        self, action: str, actor: str = "system", target: str = "", result: str = "success", **kwargs
    ) -> AuditEntry:
        return self.log(
            AuditCategory.EXPLOIT,
            action,
            actor=actor,
            target=target,
            result=result,
            severity=AuditSeverity.CRITICAL,
            details=kwargs,
        )

    def log_user(
        self, action: str, actor: str = "system", target: str = "", result: str = "success", **kwargs
    ) -> AuditEntry:
        return self.log(AuditCategory.USER, action, actor=actor, target=target, result=result, details=kwargs)

    def log_config(self, action: str, actor: str = "system", result: str = "success", **kwargs) -> AuditEntry:
        return self.log(
            AuditCategory.CONFIG, action, actor=actor, result=result, severity=AuditSeverity.WARNING, details=kwargs
        )

    def log_system(self, action: str, result: str = "success", **kwargs) -> AuditEntry:
        return self.log(AuditCategory.SYSTEM, action, result=result, details=kwargs)
