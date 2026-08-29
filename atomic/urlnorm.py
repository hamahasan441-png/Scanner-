"""
URL normalization for the ``atomic`` wrapper and the engine.

A user typing ``example.com`` should Just Work, not silently fail.
The historical behaviour required ``http://`` or ``https://`` prefixes
and returned a 400 in the dashboard. This module centralises the
"be liberal in what you accept" rule.

Acceptance rules:

  1. If the input already has a scheme (``http://`` / ``https://``),
     return it unchanged after light cleanup (strip whitespace, strip
     trailing slash *except* when the path is ``/``).
  2. If the input is a bare hostname (``example.com``,
     ``sub.example.com``, ``192.168.1.1``), or a host:port
     (``example.com:8080``) or a host with a path
     (``example.com/admin``), prepend ``https://`` by default.
  3. ``localhost`` and ``*.localhost`` and RFC1918 IPs (10/8, 172.16/12,
     192.168/16, 127/8) get ``http://`` (they are almost never
     reachable over HTTPS in a dev environment).
  4. Empty / whitespace-only input is rejected.
  5. The scheme can be forced via the ``ATOMIC_DEFAULT_SCHEME`` env var
     (``http`` or ``https``) — overrides rule 3.

The module is intentionally dependency-free so it can be imported by
both the wrapper and the engine without dragging in requests / flask.
"""
from __future__ import annotations

import os
import re
from typing import Optional
from urllib.parse import urlparse, urlunparse, quote


# Conservative: hostnames / IPs / host:port / host/path?query
# We do NOT match anything containing a space, a control char, or a
# scheme. This keeps the normalisation safe.
_HOST_LIKE = re.compile(
    r"^(?=.{1,2048}$)"                      # length cap
    r"(?=^[^/\s?#]+(?::\d+)?(?:[/\?#].*)?$)"  # no whitespace; optional :port, path, query
    r"[A-Za-z0-9._%\-]+"                      # the host part itself
    r"(?::\d+)?"                              # optional port
    r"(?:[/\?#].*)?$"                         # optional path / query / fragment
)

# RFC1918 + loopback + link-local — see the SCOPE/RFC discussion.
_RFC1918_NETWORKS = (
    re.compile(r"^10\."),                  # 10.0.0.0/8
    re.compile(r"^192\.168\."),            # 192.168.0.0/16
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),  # 172.16.0.0/12
    re.compile(r"^127\."),                 # 127.0.0.0/8 loopback
    re.compile(r"^0\.0\.0\.0$"),
    re.compile(r"^::1$"),
    re.compile(r"^fe80:", re.IGNORECASE),  # link-local IPv6
)


def _is_private_or_localhost(host: str) -> bool:
    """Return True if the host is loopback, RFC1918, or link-local."""
    if not host:
        return False
    h = host.lower().strip("[]")
    if h in ("localhost", "ip6-localhost", "ip6-loopback"):
        return True
    if h.endswith(".localhost") or h.endswith(".local"):
        return True
    for pat in _RFC1918_NETWORKS:
        if pat.match(h):
            return True
    return False


def _default_scheme(host: str) -> str:
    """Return the scheme to use when none was given."""
    forced = os.environ.get("ATOMIC_DEFAULT_SCHEME", "").strip().lower()
    if forced in ("http", "https"):
        return forced
    if _is_private_or_localhost(host):
        return "http"
    return "https"


def normalize(target: str, *, default_scheme: Optional[str] = None) -> str:
    """Return a fully-qualified URL the engine can hand to the requester.

    >>> normalize("example.com")
    'https://example.com/'
    >>> normalize("http://example.com")
    'http://example.com/'
    >>> normalize("https://example.com/admin/")
    'https://example.com/admin/'
    >>> normalize("localhost:5000")
    'http://localhost:5000/'
    >>> normalize("192.168.1.10:8080/api")
    'http://192.168.1.10:8080/api'

    Raises ``ValueError`` for empty / unparseable input.
    """
    if target is None:
        raise ValueError("target is None")
    raw = str(target).strip()
    if not raw:
        raise ValueError("target is empty")

    # Already has a scheme? Clean and return.
    if "://" in raw:
        parsed = urlparse(raw)
        if parsed.scheme.lower() not in ("http", "https"):
            raise ValueError(
                f"unsupported scheme {parsed.scheme!r} in target {raw!r}; "
                f"use http:// or https://"
            )
        if not parsed.netloc:
            raise ValueError(f"target {raw!r} is missing a hostname")
        # Normalise path: keep "" as "/" so downstream code can rely on it.
        path = parsed.path or "/"
        return urlunparse((parsed.scheme.lower(), parsed.netloc, path,
                           parsed.params, parsed.query, parsed.fragment))

    # No scheme — try to match as a bare host[:port][/path][?query][#frag].
    if not _HOST_LIKE.match(raw):
        raise ValueError(
            f"target {raw!r} is not a recognisable URL or hostname"
        )

    # urlparse with a forced http scheme is the safe way to split a
    # bare host into netloc + path.
    parsed = urlparse("http://" + raw)
    host = parsed.hostname or ""
    if not host:
        raise ValueError(f"target {raw!r} has no hostname")

    # SECURITY: Reject single-label hostnames without dot (e.g., "not-a-url")
    # unless they are localhost, private, or numeric IP (decimal/hex)
    # This prevents ambiguous inputs from being treated as valid targets and
    # matches the expectation of tests that "not-a-url" should be rejected.
    # We allow:
    # - localhost and *.localhost, *.local
    # - RFC1918, loopback, link-local
    # - Pure numeric (decimal IP like 2130706433) or hex (0x7f000001)
    # - Hosts containing dot (example.com) or colon (IPv6)
    if "." not in host and ":" not in host:
        # Check if it's numeric or hex IP representation
        is_numeric_ip = host.isdigit() or (host.lower().startswith("0x") and all(c in "0123456789abcdef" for c in host.lower()[2:]))
        if not (is_numeric_ip or _is_private_or_localhost(host)):
            # Also allow if host is exactly "localhost" handled by _is_private_or_localhost, so this is truly single-label public
            raise ValueError(f"target {raw!r} is not a valid hostname (single-label without dot)")

    scheme = (default_scheme or _default_scheme(host)).lower()
    if scheme not in ("http", "https"):
        scheme = "https"
    # Preserve port if any.
    port = parsed.port
    netloc = host if not port else f"{host}:{port}"
    path = parsed.path or "/"
    # Don't re-quote; the user input is taken as-is.
    return urlunparse((scheme, netloc, quote(path, safe="/"), parsed.params,
                       parsed.query, parsed.fragment))


def is_acceptable_target(target: str) -> bool:
    """Return True if ``target`` is something the engine can scan.

    This is the *non-throwing* counterpart of :func:`normalize` and is
    used by the web API to short-circuit obviously bad input.
    """
    try:
        normalize(target)
        return True
    except (ValueError, TypeError):
        return False
