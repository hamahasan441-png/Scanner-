#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Coverage-Guided Fuzzing Module
API fuzzing, parameter fuzzing, header fuzzing with coverage feedback.
"""
import random
import string
from config import Colors
from modules.base import BaseModule


class CoverageFuzzModule(BaseModule):
    """Coverage-guided fuzzing module."""

    name = "Coverage Fuzzing"
    vuln_type = "fuzz"

    MUTATIONS = [
        "", "\x00", "A" * 10000, "-1", "0", "999999999",
        "true", "false", "null", "undefined", "NaN", "Infinity",
        "../../../", "file:///etc/passwd", "{{7*7}}", "${7*7}",
        "<script>alert(1)</script>", "' OR 1=1 --",
        "\xff\xfe", "\xef\xbb\xbf", "%00", "\r\n",
        "[]", "{}", "[]string", "1e999",
        "$(id)", "`id`", "|id", ";id",
    ]

    def test_url(self, url):
        pass

    def test(self, url, method, param, value):
        """Fuzz parameter with various mutations."""
        for mutation in self.MUTATIONS[:8]:
            try:
                if method.upper() == "GET":
                    resp = self.requester.request(url, "GET", data={param: mutation})
                else:
                    resp = self.requester.request(url, "POST", data={param: mutation})
                if resp and resp.status_code == 500:
                    self.engine.add_finding(self._finding(
                        technique="Server Error (Fuzzing)",
                        url=url,
                        severity="MEDIUM",
                        confidence=0.5,
                        param=param,
                        payload=repr(mutation)[:100],
                        evidence=f"Server returned 500 for mutation: {repr(mutation)[:50]}",
                    ))
            except Exception:
                pass

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
