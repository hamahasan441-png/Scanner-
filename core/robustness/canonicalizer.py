#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bounded canonicalization for defensive security analysis.

The canonicalizer produces a *security view* of untrusted text.  It never
executes shell syntax, expands environment variables, resolves filesystem globs,
or treats decoding as permission to execute decoded content.
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass
from typing import Tuple
from urllib.parse import unquote

MAX_DECODE_DEPTH = 4
MAX_DECODED_BYTES = 64 * 1024
MAX_EXPANSION_RATIO = 8

_ZERO_WIDTH = {"\u200b", "\u200c", "\u200d", "\ufeff", "\u2060"}
_COMMENT_RE = re.compile(r"/\*.*?\*/", flags=re.DOTALL)
_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")

# Small, deliberately conservative confusable map used only for the security
# view.  Raw text is always retained for audit/reporting.
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "у": "y", "к": "k", "м": "m", "т": "t", "н": "h", "в": "b",
    "Α": "a", "Β": "b", "Ε": "e", "Ζ": "z", "Η": "h", "Ι": "i",
    "Κ": "k", "Μ": "m", "Ν": "n", "Ο": "o", "Ρ": "p", "Τ": "t",
    "Χ": "x", "Υ": "y", "α": "a", "ο": "o", "ρ": "p", "χ": "x",
})

# Leetspeak normalization is intentionally narrow.  It is a signal-recovery
# transform, not a claim that every digit is equivalent to a letter.
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"})


@dataclass(frozen=True)
class CanonicalizedText:
    raw: str
    normalized: str
    transforms: Tuple[str, ...]
    decode_depth: int
    truncated: bool = False


def _decode_bytes(data: bytes) -> str | None:
    if len(data) > MAX_DECODED_BYTES:
        return None
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            return None
    for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
        try:
            text = data.decode(encoding)
        except UnicodeDecodeError:
            continue
        # Prefer plausible printable text.  This avoids treating arbitrary
        # binary blobs as instructions.
        if text and sum(ch.isprintable() or ch.isspace() for ch in text) / len(text) >= 0.85:
            return text
    return None


def _maybe_decode_base64(text: str) -> str | None:
    compact = "".join(text.split())
    if len(compact) < 8 or len(compact) % 4 != 0 or not _B64_RE.fullmatch(compact):
        return None
    try:
        data = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(data) > MAX_DECODED_BYTES:
        return None
    return _decode_bytes(data)


def canonicalize_security_text(value: str) -> CanonicalizedText:
    raw = str(value or "")
    text = raw
    transforms: list[str] = []
    depth = 0
    truncated = False

    if len(text.encode("utf-8", errors="ignore")) > MAX_DECODED_BYTES:
        text = text[:MAX_DECODED_BYTES]
        truncated = True
        transforms.append("input_truncated")

    # Bounded recursive URL/Base64 decoding for inspection only.
    baseline_size = max(1, len(text.encode("utf-8", errors="ignore")))
    for _ in range(MAX_DECODE_DEPTH):
        changed = False
        url_decoded = unquote(text)
        if url_decoded != text:
            text = url_decoded
            transforms.append("url_decode")
            changed = True
            depth += 1

        b64_decoded = _maybe_decode_base64(text)
        if b64_decoded is not None and b64_decoded != text:
            text = b64_decoded
            transforms.append("base64_decode")
            changed = True
            depth += 1

        current_size = len(text.encode("utf-8", errors="ignore"))
        if current_size > MAX_DECODED_BYTES or current_size > baseline_size * MAX_EXPANSION_RATIO:
            text = text[:MAX_DECODED_BYTES]
            truncated = True
            transforms.append("decode_limit")
            break
        if not changed or depth >= MAX_DECODE_DEPTH:
            break

    nfkc = unicodedata.normalize("NFKC", text)
    if nfkc != text:
        transforms.append("nfkc")
    text = nfkc

    no_zero = "".join(ch for ch in text if ch not in _ZERO_WIDTH)
    if no_zero != text:
        transforms.append("zero_width_removed")
    text = no_zero

    no_comments = _COMMENT_RE.sub("", text)
    if no_comments != text:
        transforms.append("comment_interleaving_removed")
    text = no_comments

    mapped = text.translate(_CONFUSABLES)
    if mapped != text:
        transforms.append("confusable_skeleton")
    text = mapped

    folded = text.casefold()
    if folded != text:
        transforms.append("casefold")
    text = folded

    leet = text.translate(_LEET)
    if leet != text:
        transforms.append("leet_normalized")
    text = leet

    collapsed_slashes = re.sub(r"/{2,}", "/", text)
    if collapsed_slashes != text:
        transforms.append("duplicate_separator_removed")
    text = collapsed_slashes

    return CanonicalizedText(
        raw=raw,
        normalized=text.strip(),
        transforms=tuple(transforms),
        decode_depth=depth,
        truncated=truncated,
    )
