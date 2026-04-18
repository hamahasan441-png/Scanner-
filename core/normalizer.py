#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v10.0 - ULTIMATE EDITION
Response Normalization Engine

Removes dynamic noise from HTTP responses BEFORE comparing them.
Without normalization, timestamps, session tokens, CSRF tokens, and
other per-request dynamic content cause false diffs and unreliable
baseline comparisons.

Usage:
    from core.normalizer import normalize

    clean = normalize(raw_html)
"""

import re

# Named pattern registry — maps YAML strip pattern names to regex implementations
_PATTERN_REGISTRY = {
    "timestamps": re.compile(r"(?:timestamp|time|_ts|_t)\s*[=:]\s*\d{10,}"),
    "request_ids": re.compile(
        r'(?:request[_-]?id|req[_-]?id|trace[_-]?id|x-request-id)\s*[=:]\s*["\']?[\w\-]+', re.IGNORECASE
    ),
    "csrf_tokens": re.compile(r'csrf[_-]?token?\s*=\s*["\']?[\w\-]+'),
    "nonces": re.compile(r'nonce\s*=\s*["\']?[\w\-]+'),
    "rotating_tokens": re.compile(r'_token\s*=\s*["\']?[\w\-]+'),
    "random_fragments": re.compile(r'(?:token|secret|key|auth)\s*[=:]\s*["\']?[a-f0-9]{32,}'),
    "session_ids": re.compile(r'session[_-]?[iI]d\s*=\s*["\']?[\w\-]+'),
    "set_cookies": re.compile(r"Set-Cookie:.*", re.IGNORECASE),
}

# Default patterns used when no rules engine config is available
_DYNAMIC_PATTERNS = [
    _PATTERN_REGISTRY["timestamps"],
    _PATTERN_REGISTRY["session_ids"],
    _PATTERN_REGISTRY["csrf_tokens"],
    _PATTERN_REGISTRY["nonces"],
    _PATTERN_REGISTRY["rotating_tokens"],
    _PATTERN_REGISTRY["random_fragments"],
    _PATTERN_REGISTRY["set_cookies"],
]

# Whitespace normalization
_MULTI_SPACE = re.compile(r"\s+")

# Active strip patterns (can be configured by rules engine)
_active_patterns = None


def configure_strip_patterns(pattern_names):
    """Configure which strip patterns are active based on rules-engine names.

    Args:
        pattern_names: list of pattern name strings from the YAML config.
    """
    global _active_patterns
    _active_patterns = []
    for name in pattern_names:
        if name in _PATTERN_REGISTRY:
            _active_patterns.append(_PATTERN_REGISTRY[name])
        # Unknown names are silently ignored (forward compatibility)


def normalize(html):
    """Normalize an HTML response body by removing dynamic noise.

    Strips timestamps, session/CSRF tokens, long hex strings, and
    collapses whitespace so that two responses that differ only in
    dynamic content will compare as equal.

    Uses rules-engine-configured patterns when available, otherwise
    falls back to default patterns.

    Args:
        html: Raw response body text.

    Returns:
        Cleaned string suitable for stable comparison.
    """
    if not html:
        return ""

    patterns = _active_patterns if _active_patterns is not None else _DYNAMIC_PATTERNS

    for pattern in patterns:
        html = pattern.sub("", html)

    html = _MULTI_SPACE.sub(" ", html).strip()
    return html
