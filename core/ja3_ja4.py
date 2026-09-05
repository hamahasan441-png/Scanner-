#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — Client TLS/HTTP2 Fingerprint Rotation

⚠️ FOR AUTHORIZED TESTING ONLY ⚠️

Provides a small palette of client TLS+HTTP2 fingerprints (JA3 / JA4 /
Akamai fingerprint) and a helper that returns per-request adapter
overrides. The requester layer applies them when the operator opts in
via ``--ja3-rotate`` or ``config['ja3_rotate']=True``. Purely a
CLIENT-side evasion; nothing here touches the target's config.

Why: Cloudflare, Akamai, PerimeterX, Datadome and modern bot-detect
match on the TLS ClientHello + HTTP/2 SETTINGS order. Python-requests
+ urllib3 emit a very distinctive fingerprint that many defenders
score outright as "bot." Rotating between browser-shaped fingerprints
multiplies real-world reach of every other module.

This file ships the PROFILE DATA and the rotation policy. The actual
socket-level rewriting requires either:

  * ``curl-cffi`` (drop-in requests replacement that speaks JA3),
  * ``tls-client`` (bogdanfinn/tls-client Python binding), or
  * ``pyca/cryptography`` with a hand-rolled OpenSSL cipher list.

We prefer curl-cffi when installed — it's the least-invasive
integration. When neither library is present, ``get_active_profile``
returns None and the requester falls back to its default stack (the
operator gets a one-line warning). The framework never silently
degrades protection promises.
"""
from __future__ import annotations

import itertools
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Profile catalog
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class TLSProfile:
    """A single client fingerprint bundle.

    ``curl_impersonate_name`` names a curl-cffi impersonation target.
    ``ja3`` is the classic 6-field JA3 string (informational; the
    requester uses curl-cffi's built-in mapping in practice).
    """
    label: str
    curl_impersonate_name: str  # e.g. "chrome124", "safari17_0", "firefox133"
    ja3: str = ""
    ja4: str = ""
    http2_settings_order: tuple[str, ...] = field(default_factory=tuple)
    user_agent: str = ""


# Curated set — each is a currently-in-support browser fingerprint that
# curl-cffi ships an impersonation profile for. Update these as new
# curl-cffi releases add profiles.
_PROFILES: tuple[TLSProfile, ...] = (
    TLSProfile(
        label="chrome-desktop-latest",
        curl_impersonate_name="chrome124",
        ja4="t13d1516h2_8daaf6152771_02713d6af862",
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        ),
    ),
    TLSProfile(
        label="firefox-desktop-latest",
        curl_impersonate_name="firefox133",
        ja4="t13d1717h2_5b57614c22b0_93c746dc12af",
        user_agent=(
            "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 "
            "Firefox/133.0"
        ),
    ),
    TLSProfile(
        label="safari-mac-latest",
        curl_impersonate_name="safari17_0",
        ja4="t13d2014h2_a09f3c656075_14788d8d241b",
        user_agent=(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/17.0 Safari/605.1.15"
        ),
    ),
    TLSProfile(
        label="chrome-android",
        curl_impersonate_name="chrome_android",
        user_agent=(
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"
        ),
    ),
    TLSProfile(
        label="edge-desktop-latest",
        curl_impersonate_name="edge_128",
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0"
        ),
    ),
)


# --------------------------------------------------------------------------- #
# Rotation state
# --------------------------------------------------------------------------- #

class _Rotator:
    """Round-robin over the profile catalog.

    Thread-safe enough for the scanner's typical usage: worker threads
    call `next()`; if two threads land on the same profile they still
    both work — the goal is diversity across requests, not strict
    single-assignment.
    """
    def __init__(self, profiles: tuple[TLSProfile, ...]) -> None:
        self._cycle = itertools.cycle(profiles)
        self._sticky: Optional[TLSProfile] = None

    def stick(self, label: str) -> Optional[TLSProfile]:
        """Pin the rotator to a specific profile by label. Returns
        the matched profile or None if not found."""
        for p in _PROFILES:
            if p.label == label:
                self._sticky = p
                return p
        self._sticky = None
        return None

    def next(self) -> TLSProfile:
        if self._sticky:
            return self._sticky
        return next(self._cycle)


_rotator = _Rotator(_PROFILES)


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def profiles() -> tuple[TLSProfile, ...]:
    """Return the full catalog (for the requester's warm-up print, etc)."""
    return _PROFILES


def get_active_profile(*, sticky_label: Optional[str] = None) -> Optional[TLSProfile]:
    """Return the profile the next request should use, or None if the
    prerequisite library (curl-cffi / tls-client) is not installed.

    ``sticky_label`` pins to a specific profile for the remainder of
    the scan — useful for reproducibility (bug reports).
    """
    if not _library_available():
        return None
    if sticky_label:
        return _rotator.stick(sticky_label)
    return _rotator.next()


def build_session(sticky_label: Optional[str] = None):
    """Return a session-like object that speaks the active profile's
    TLS fingerprint. Callers should use the returned object exactly as
    they would `requests.Session()`. Returns None if no impersonation
    backend is installed."""
    prof = get_active_profile(sticky_label=sticky_label)
    if prof is None:
        return None
    try:
        # Preferred backend
        import curl_cffi.requests as _cffi
        sess = _cffi.Session(impersonate=prof.curl_impersonate_name)
        if prof.user_agent:
            sess.headers.update({"User-Agent": prof.user_agent})
        return sess
    except Exception as exc:
        logger.debug("curl_cffi session build failed for %s: %s", prof.label, exc)
        return None


# --------------------------------------------------------------------------- #
# Internal
# --------------------------------------------------------------------------- #

def _library_available() -> bool:
    try:
        import curl_cffi  # noqa: F401
        return True
    except Exception:
        pass
    try:
        import tls_client  # noqa: F401
        return True
    except Exception:
        pass
    return False


def library_hint() -> str:
    """Human-friendly hint for the operator when no backend is present.
    The requester prints this once per scan when --ja3-rotate is on and
    no library is installed."""
    return (
        "JA3/JA4 rotation requested but no impersonation backend is "
        "installed. Install `curl-cffi` (recommended) or `tls-client` "
        "to enable browser-shaped ClientHello + HTTP/2 fingerprints. "
        "Falling back to the default requests stack (single, distinctive "
        "Python-requests fingerprint)."
    )
