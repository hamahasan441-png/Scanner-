#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — Session & Cookie Hygiene

Audits the cookies the target sets for the common weaknesses that no
other module owns end-to-end: missing Secure, missing HttpOnly,
missing SameSite, missing __Host- / __Secure- prefixes on session
cookies, and cookie names that suggest session state stored client-
side unencrypted.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from modules.base import BaseModule


_SESSION_NAME_RE = re.compile(
    r"^(session|sess|sid|jsessionid|phpsessid|asp\.?net_sessionid|"
    r"connect\.sid|auth|token|access_token|refresh_token|jwt)$",
    re.IGNORECASE,
)


def _parse_set_cookies(headers) -> list[dict]:
    """Return one dict per Set-Cookie header with attributes normalized."""
    result = []
    raw_list = []
    if hasattr(headers, "get_all"):
        raw_list = headers.get_all("Set-Cookie") or []
    else:
        # requests.Response.headers is CaseInsensitiveDict; multi-cookie
        # arrives comma-joined which is ambiguous for Expires — best-
        # effort split on ", " that's followed by "<name>=".
        raw = headers.get("Set-Cookie", "")
        if raw:
            raw_list = re.split(r",\s+(?=[A-Za-z0-9_\-]+=)", raw)
    for raw in raw_list:
        parts = [p.strip() for p in raw.split(";") if p.strip()]
        if not parts:
            continue
        name_val = parts[0]
        if "=" not in name_val:
            continue
        name = name_val.split("=", 1)[0]
        entry = {"name": name, "attrs": {a.split("=", 1)[0].lower(): (a.split("=", 1)[1] if "=" in a else True)
                                          for a in parts[1:]}}
        result.append(entry)
    return result


class SessionCookieModule(BaseModule):
    """Cookie hygiene checks — one finding per issue per cookie."""

    name = "Session/Cookie Hygiene"
    vuln_type = "session_cookie"

    def test(self, url: str, method: str, param: str, value: str):
        pass

    def test_url(self, url: str):
        parsed = urlparse(url)
        try:
            resp = self.requester.request(url, "GET")
        except Exception:
            return
        if resp is None:
            return
        cookies = _parse_set_cookies(resp.headers)
        is_https = parsed.scheme == "https"
        for c in cookies:
            self._audit(url, c, is_https)

    def _audit(self, url: str, cookie: dict, is_https: bool):
        name = cookie["name"]
        attrs = cookie["attrs"]
        is_session = bool(_SESSION_NAME_RE.match(name))
        severity_bump = "HIGH" if is_session else "LOW"

        if is_https and "secure" not in attrs:
            self._emit(url, name, "Cookie missing Secure attribute",
                       severity_bump, 0.95,
                       f"{name} is set over HTTPS but lacks Secure — sniffable on mixed content")

        if is_session and "httponly" not in attrs:
            self._emit(url, name, "Session cookie missing HttpOnly",
                       "HIGH", 0.95,
                       f"{name} is JS-readable; XSS can steal the session")

        if is_session and "samesite" not in attrs:
            self._emit(url, name, "Session cookie missing SameSite",
                       "MEDIUM", 0.9,
                       f"{name} has no SameSite attribute — cross-site CSRF surface")

        if is_session and name.startswith("__Host-") is False and name.startswith("__Secure-") is False:
            if is_https:
                self._emit(url, name, "Session cookie missing __Host-/__Secure- prefix",
                           "LOW", 0.75,
                           f"Session cookie {name} could adopt __Host- prefix for stricter binding")

        # Wide-open Domain attribute on a session cookie (parent-domain
        # cookie tossing risk).
        domain = attrs.get("domain")
        if is_session and isinstance(domain, str) and domain.startswith("."):
            self._emit(url, name, "Session cookie scoped to parent domain",
                       "MEDIUM", 0.85,
                       f"{name} Domain={domain} — any subdomain can read/overwrite it")

    def _emit(self, url, cookie_name, technique, severity, confidence, evidence):
        from core.engine import Finding
        self.engine.add_finding(Finding(
            technique=technique,
            url=url,
            severity=severity,
            confidence=confidence,
            param=cookie_name,
            payload="",
            evidence=evidence,
        ))
