#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK
Philosophy Layer — Append-only HMAC-signed Evidence Ledger
============================================================

Every evidence item carries a chained HMAC-SHA256: the signature of
entry N covers entry N's payload AND the signature of entry N-1.
Reordering, deletion or tampering breaks the chain at the affected
entry and at every entry that follows.

The ledger is for *our own discipline* — we want every finding to be
fully replayable and tamper-evident. It is not designed for legal
attestation.

See PHILOSOPHY.md §4.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional


GENESIS_PREV = "0" * 64


def _canonical(obj) -> bytes:
    """Stable JSON encoding for HMAC input."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")




@dataclass
class LedgerEntry:
    """One signed entry in the evidence chain."""

    seq: int
    timestamp: float
    hypothesis_id: str
    oracle: str
    positive: bool
    effect_size: float
    p_value: float
    request_hash: str = ""
    response_hash: str = ""
    detail: str = ""
    prev_sig: str = GENESIS_PREV
    sig: str = ""

    def payload_for_sig(self) -> bytes:
        """Bytes covered by ``sig``: the entry minus the signature."""
        d = asdict(self)
        d.pop("sig", None)
        return _canonical(d)

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)




class EvidenceLedger:
    """Thread-safe append-only HMAC-chained ledger."""

    def __init__(self, key: Optional[bytes] = None, path: Optional[str] = None):
        if key is None:
            key = os.environ.get("ATOMIC_LEDGER_KEY", "").encode("utf-8")
            if not key:
                # Per-instance key. Sufficient for in-process integrity.
                key = os.urandom(32)
        self._key = key
        self._path = path
        self._lock = threading.Lock()
        self._entries: List[LedgerEntry] = []
        self._last_sig = GENESIS_PREV

    def _sign(self, payload: bytes) -> str:
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def append(
        self,
        hypothesis_id: str,
        oracle: str,
        positive: bool,
        effect_size: float = 0.0,
        p_value: float = 1.0,
        request_hash: str = "",
        response_hash: str = "",
        detail: str = "",
    ) -> LedgerEntry:
        """Append one observation to the ledger and return the signed entry."""
        with self._lock:
            entry = LedgerEntry(
                seq=len(self._entries),
                timestamp=time.time(),
                hypothesis_id=hypothesis_id,
                oracle=oracle,
                positive=positive,
                effect_size=float(effect_size),
                p_value=float(p_value),
                request_hash=request_hash,
                response_hash=response_hash,
                detail=detail,
                prev_sig=self._last_sig,
            )
            entry.sig = self._sign(entry.payload_for_sig())
            self._entries.append(entry)
            self._last_sig = entry.sig
            if self._path:
                self._flush_one(entry)
            return entry



    def _flush_one(self, entry: LedgerEntry) -> None:
        try:
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry.to_dict(), sort_keys=True) + "\n")
        except OSError:
            # The ledger is best-effort persistence; a write failure
            # should not break the scan.
            pass

    def verify(self) -> bool:
        """Re-verify the chain. Returns True iff every entry is intact."""
        with self._lock:
            prev = GENESIS_PREV
            for i, entry in enumerate(self._entries):
                if entry.prev_sig != prev:
                    return False
                expected = self._sign(entry.payload_for_sig())
                if not hmac.compare_digest(expected, entry.sig):
                    return False
                if entry.seq != i:
                    return False
                prev = entry.sig
            return True

    def slice_for(self, hypothesis_id: str) -> List[LedgerEntry]:
        """Return all ledger entries for one hypothesis (in order)."""
        with self._lock:
            return [e for e in self._entries if e.hypothesis_id == hypothesis_id]

    def head_sig(self) -> str:
        """Return the signature of the most recent entry (or genesis)."""
        with self._lock:
            return self._last_sig

    def size(self) -> int:
        with self._lock:
            return len(self._entries)



    def export(self) -> List[Dict[str, object]]:
        """Snapshot the ledger as a list of dicts (suitable for JSON)."""
        with self._lock:
            return [e.to_dict() for e in self._entries]


def hash_request(method: str, url: str, headers: Dict, body: str) -> str:
    """Stable hash of an HTTP request for ledger entries."""
    payload = _canonical({
        "body_sha256": hashlib.sha256((body or "").encode()).hexdigest(),
        "headers": {k.lower(): v for k, v in (headers or {}).items()
                    if k.lower() not in {"authorization", "cookie", "x-api-key"}},
        "method": (method or "").upper(),
        "url": url,
    })
    return hashlib.sha256(payload).hexdigest()


def hash_response(status: int, headers: Dict, body: str) -> str:
    payload = _canonical({
        "body_sha256": hashlib.sha256((body or "").encode()).hexdigest(),
        "headers": dict(headers or {}),
        "status": int(status or 0),
    })
    return hashlib.sha256(payload).hexdigest()


__all__ = [
    "EvidenceLedger",
    "LedgerEntry",
    "GENESIS_PREV",
    "hash_request",
    "hash_response",
]
