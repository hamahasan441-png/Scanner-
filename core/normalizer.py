#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v9.0 - ULTIMATE EDITION
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

# Patterns that introduce per-request noise
_DYNAMIC_PATTERNS = [
    re.compile(r'(?:timestamp|time|_ts|_t)\s*[=:]\s*\d{10,}'),  # timestamps in key=value contexts
    re.compile(r'session[_-]?[iI]d\s*=\s*["\']?[\w\-]+'),  # session=... / session_id=...
    re.compile(r'csrf[_-]?token?\s*=\s*["\']?[\w\-]+'),     # csrf=... / csrf_token=...
    re.compile(r'nonce\s*=\s*["\']?[\w\-]+'),                # nonce=...
    re.compile(r'_token\s*=\s*["\']?[\w\-]+'),               # _token=...
    re.compile(r'(?:token|secret|key|auth)\s*[=:]\s*["\']?[a-f0-9]{32,}'),  # hex tokens in key=value
    re.compile(r'Set-Cookie:.*', re.IGNORECASE),             # Set-Cookie headers in body
]

# Whitespace normalization
_MULTI_SPACE = re.compile(r'\s+')


def normalize(html):
    """Normalize an HTML response body by removing dynamic noise.

    Strips timestamps, session/CSRF tokens, long hex strings, and
    collapses whitespace so that two responses that differ only in
    dynamic content will compare as equal.

    Args:
        html: Raw response body text.

    Returns:
        Cleaned string suitable for stable comparison.
    """
    if not html:
        return ''

    for pattern in _DYNAMIC_PATTERNS:
        html = pattern.sub('', html)

    html = _MULTI_SPACE.sub(' ', html).strip()
    return html
