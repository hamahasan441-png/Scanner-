#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Typosquatting & Supply Chain Module
Typosquatting detection, dependency confusion, malicious package indicators.
"""
import re
from config import Colors
from modules.base import BaseModule


class TyposquattingModule(BaseModule):
    """Supply chain attack detection module."""

    name = "Typosquatting & Supply Chain"
    vuln_type = "supply_chain"

    def test_url(self, url):
        self._test_dependency_files(url)
        self._test_source_maps(url)

    def test(self, url, method, param, value):
        pass

    def _test_dependency_files(self, url):
        """Check for exposed dependency files that reveal the supply chain."""
        from urllib.parse import urlparse, urljoin
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        dep_files = [
            "/package.json", "/package-lock.json", "/yarn.lock",
            "/composer.json", "/composer.lock", "/Gemfile", "/Gemfile.lock",
            "/requirements.txt", "/Pipfile", "/poetry.lock",
            "/go.mod", "/go.sum", "/Cargo.toml", "/Cargo.lock",
            "/pom.xml", "/build.gradle", "/build.gradle.kts",
        ]
        for path in dep_files:
            try:
                test_url = base + path
                resp = self.requester.request(test_url, "GET", timeout=5)
                if resp and resp.status_code == 200 and len(resp.text) > 10:
                    self.engine.add_finding(self._finding(
                        technique="Dependency File Exposure",
                        url=test_url,
                        severity="MEDIUM",
                        confidence=0.9,
                        param=path,
                        payload=test_url,
                        evidence=f"Dependency file exposed: {path} ({len(resp.text)} bytes)",
                    ))
            except Exception:
                pass

    def _test_source_maps(self, url):
        """Check for exposed source maps."""
        from urllib.parse import urlparse, urljoin
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        map_files = ["/main.js.map", "/app.js.map", "/bundle.js.map", "/vendor.js.map"]
        for path in map_files:
            try:
                test_url = base + path
                resp = self.requester.request(test_url, "GET", timeout=5)
                if resp and resp.status_code == 200 and "mappings" in resp.text:
                    self.engine.add_finding(self._finding(
                        technique="Source Map Exposure",
                        url=test_url,
                        severity="MEDIUM",
                        confidence=0.95,
                        param=path,
                        payload=test_url,
                        evidence=f"Source map exposed: {path} — reveals original source code",
                    ))
            except Exception:
                pass

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
