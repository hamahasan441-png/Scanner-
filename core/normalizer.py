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
    "timestamps": re.compile(r"(?:timestamp|time|_ts|_t|date)\s*[=:]\s*\d{10,}"),
    "request_ids": re.compile(
        r'(?:request[_-]?id|req[_-]?id|trace[_-]?id|x-request-id|correlation[_-]?id)\s*[=:]\s*["\']?[\w\-]+',
        re.IGNORECASE,
    ),
    "csrf_tokens": re.compile(r'csrf[_-]?token?\s*[=:]\s*["\']?[\w\-]+'),
    "nonces": re.compile(r'nonce\s*=\s*["\']?[\w\-]+'),
    "rotating_tokens": re.compile(r'_token\s*=\s*["\']?[\w\-]+'),
    "random_fragments": re.compile(r'(?:token|secret|key|auth|csrf|nonce)\s*[=:]\s*["\']?[a-f0-9]{32,}'),
    "session_ids": re.compile(r'session[_-]?[iI]d\s*=\s*["\']?[\w\-]+'),
    "set_cookies": re.compile(r"Set-Cookie:.*", re.IGNORECASE),
    "unix_timestamps": re.compile(r"\b1[6-9]\d{8}\b"),  # Unix timestamps (2020-2033)
    "iso_dates": re.compile(
        r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
    ),
    "uuid_values": re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE),
    "cache_busters": re.compile(r'[?&](?:_|cb|t|v|cache|bust)\s*=\s*\d+'),
    "dynamic_ids": re.compile(r'(?:id|ref|txn|transaction)\s*[=:]\s*["\']?[a-zA-Z0-9\-_]{16,}'),
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
    _PATTERN_REGISTRY["unix_timestamps"],
    _PATTERN_REGISTRY["iso_dates"],
    _PATTERN_REGISTRY["uuid_values"],
    _PATTERN_REGISTRY["cache_busters"],
    _PATTERN_REGISTRY["dynamic_ids"],
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

    Strips timestamps, session/CSRF tokens, long hex strings, UUIDs,
    ISO dates, and collapses whitespace so that two responses that
    differ only in dynamic content will compare as equal.

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


def normalize_for_comparison(text_a, text_b):
    """Normalize two texts and return them ready for comparison.

    Convenience function that applies normalize() to both texts
    and returns a tuple of (normalized_a, normalized_b).
    """
    return normalize(text_a), normalize(text_b)


def structural_similarity(text_a, text_b):
    """Calculate structural similarity ratio between two normalized texts.

    Returns a float between 0.0 (completely different) and 1.0 (identical).
    Uses sequence matching on normalized content.
    """
    norm_a = normalize(text_a)
    norm_b = normalize(text_b)

    if not norm_a and not norm_b:
        return 1.0
    if not norm_a or not norm_b:
        return 0.0

    # Quick length-based pre-check
    len_a, len_b = len(norm_a), len(norm_b)
    max_len = max(len_a, len_b)
    if max_len == 0:
        return 1.0

    # Length ratio as a quick similarity proxy (avoids expensive difflib)
    length_ratio = min(len_a, len_b) / max_len

    # For very different lengths, no need for deeper comparison
    if length_ratio < 0.5:
        return length_ratio

    # Character-level overlap (faster than difflib for large texts)
    # Sample first 2000 chars for performance
    sample_a = norm_a[:2000]
    sample_b = norm_b[:2000]

    if sample_a == sample_b:
        return 1.0

    # Count matching characters at same positions
    matches = sum(1 for a, b in zip(sample_a, sample_b) if a == b)
    positional_ratio = matches / max(len(sample_a), len(sample_b), 1)

    return round(positional_ratio * 0.7 + length_ratio * 0.3, 3)
