#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v11.0 — Dependency Confusion / Supply Chain Module
===================================================================

Detects supply chain attack vectors:
  - Scans discovered JavaScript bundles for private npm package names
  - Checks if those names exist on the public npm registry (potential takeover)
  - Detects exposed package.json, package-lock.json, requirements.txt etc.
  - Checks for sensitive dependency metadata (internal package registries)

Enabled with: ``--dep-confusion``
"""

from __future__ import annotations

import json
import re
import urllib.parse
from typing import List, Optional, Set

from modules.base import BaseModule


class DependencyConfusionModule(BaseModule):
    """Dependency confusion and supply chain attack surface detection."""

    name = "Dependency Confusion"
    vuln_type = "dep_confusion"

    # Files that expose dependency info
    DEP_FILES = [
        "/package.json",
        "/package-lock.json",
        "/yarn.lock",
        "/requirements.txt",
        "/Pipfile",
        "/Pipfile.lock",
        "/setup.py",
        "/pyproject.toml",
        "/Gemfile",
        "/Gemfile.lock",
        "/composer.json",
        "/composer.lock",
        "/.npmrc",
        "/.yarnrc",
        "/pom.xml",
        "/build.gradle",
        "/go.sum",
        "/go.mod",
        "/Cargo.toml",
    ]

    # Internal/private npm registry patterns
    PRIVATE_REGISTRY_PATTERNS = [
        r"registry\s*=\s*https?://(?!registry\.npmjs\.org)",
        r"@[a-z][a-z0-9-]+/",  # scoped package
        r"\"resolved\"\s*:\s*\"https?://(?!registry\.npmjs\.org)",
    ]

    # Common JS bundle patterns that expose package names
    BUNDLE_PACKAGE_PATTERNS = [
        r'require\(["\'](@?[a-z][a-z0-9_/-]+)["\']\)',
        r'from\s+["\'](@?[a-z][a-z0-9_/-]+)["\']',
        r'"name"\s*:\s*"(@?[a-z][a-z0-9_/-]+)"',
    ]

    # npm registry check URL
    NPM_REGISTRY_URL = "https://registry.npmjs.org/{package}"

    def test(self, url: str, method: str, param: str, value: str) -> None:
        """Not parameter-based — skip."""
        pass

    def test_url(self, url: str) -> None:
        """Check for exposed dependency files and JS bundles."""
        self._check_dep_files(url)
        self._check_js_bundles(url)

    # ------------------------------------------------------------------
    # Core checks
    # ------------------------------------------------------------------

    def _check_dep_files(self, url: str):
        """Check for accessible dependency manifest files."""
        parsed = urllib.parse.urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for dep_file in self.DEP_FILES:
            test_url = base + dep_file
            resp = self.requester.request(test_url, "GET")
            if not resp or resp.status_code != 200:
                continue

            body = getattr(resp, "text", "")
            if not body or len(body) < 10:
                continue

            self._emit_signal(
                vuln_type="dep_confusion",
                technique=f"Dependency Manifest Exposed: {dep_file}",
                url=test_url,
                method="GET",
                param="",
                payload="",
                evidence_text=body[:300],
                raw_confidence=0.85,
                severity="MEDIUM",
                cvss=5.3,
            )

            # Analyse package.json / package-lock.json for private packages
            if dep_file in ("/package.json", "/package-lock.json"):
                self._analyse_npm_manifest(test_url, body)

            # Check .npmrc for private registry
            if dep_file == "/.npmrc":
                self._analyse_npmrc(test_url, body)

    def _analyse_npm_manifest(self, url: str, body: str):
        """Extract package names and check for public/private confusion."""
        try:
            data = json.loads(body)
        except Exception:
            return

        packages: Set[str] = set()

        # Extract from dependencies / devDependencies
        for key in ("dependencies", "devDependencies", "peerDependencies"):
            if isinstance(data.get(key), dict):
                packages.update(data[key].keys())

        # Extract package name itself
        pkg_name = data.get("name", "")
        if pkg_name:
            packages.add(pkg_name)

        # Check each package against npm registry (limited to avoid rate limiting)
        private_candidates: List[str] = []
        for pkg in list(packages)[:20]:
            if not pkg or not re.match(r"^(@[a-z][a-z0-9-]*/)?[a-z][a-z0-9._-]*$", pkg):
                continue
            # Scoped packages or packages with internal naming conventions
            if "@" in pkg or any(
                kw in pkg.lower()
                for kw in ("internal", "private", "corp", "local", "company", "org")
            ):
                private_candidates.append(pkg)

        for pkg in private_candidates[:5]:
            if self._check_package_public(pkg):
                self._emit_signal(
                    vuln_type="dep_confusion",
                    technique=f"Dependency Confusion — Package '{pkg}' exists publicly",
                    url=url,
                    method="GET",
                    param="",
                    payload=pkg,
                    evidence_text=(
                        f"Package '{pkg}' appears private (found in manifest) "
                        f"but also exists on the public npm registry. "
                        "Potential dependency confusion attack vector."
                    ),
                    raw_confidence=0.70,
                    severity="HIGH",
                    cvss=7.3,
                )

    def _check_package_public(self, package_name: str) -> bool:
        """Check whether *package_name* exists on the public npm registry."""
        pkg_url = self.NPM_REGISTRY_URL.format(
            package=urllib.parse.quote(package_name, safe="@/")
        )
        try:
            resp = self.requester.request(pkg_url, "GET")
            return resp is not None and resp.status_code == 200
        except Exception:
            return False

    def _analyse_npmrc(self, url: str, body: str):
        """Check .npmrc for private registry configuration leakage."""
        for pattern in self.PRIVATE_REGISTRY_PATTERNS[:1]:
            if re.search(pattern, body, re.IGNORECASE):
                self._emit_signal(
                    vuln_type="dep_confusion",
                    technique="Private npm Registry Exposed in .npmrc",
                    url=url,
                    method="GET",
                    param="",
                    payload="",
                    evidence_text=body[:300],
                    raw_confidence=0.80,
                    severity="HIGH",
                    cvss=7.5,
                )
                break

        # Check for auth tokens in .npmrc
        if re.search(r"_authToken\s*=\s*[a-zA-Z0-9_\-]{20,}", body):
            self._emit_signal(
                vuln_type="dep_confusion",
                technique="npm Auth Token Exposed in .npmrc",
                url=url,
                method="GET",
                param="",
                payload="",
                evidence_text="npm _authToken found in exposed .npmrc",
                raw_confidence=0.95,
                severity="CRITICAL",
                cvss=9.1,
            )

    def _check_js_bundles(self, url: str):
        """Fetch the page and scan inline JS for private package imports."""
        resp = self.requester.request(url, "GET")
        if not resp or resp.status_code != 200:
            return

        body = getattr(resp, "text", "")
        if not body:
            return

        # Find JS bundle URLs
        js_urls = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', body)
        parsed = urllib.parse.urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        private_packages: Set[str] = set()

        for js_url in js_urls[:5]:  # limit to 5 bundles
            if not js_url.startswith("http"):
                js_url = base + js_url
            js_resp = self.requester.request(js_url, "GET")
            if not js_resp or js_resp.status_code != 200:
                continue
            js_body = getattr(js_resp, "text", "")

            for pattern in self.BUNDLE_PACKAGE_PATTERNS:
                for match in re.finditer(pattern, js_body):
                    pkg = match.group(1)
                    if "@" in pkg and "/" in pkg:
                        private_packages.add(pkg)

        for pkg in list(private_packages)[:5]:
            if self._check_package_public(pkg):
                self._emit_signal(
                    vuln_type="dep_confusion",
                    technique=f"Dependency Confusion — Scoped package '{pkg}' exists publicly",
                    url=url,
                    method="GET",
                    param="",
                    payload=pkg,
                    evidence_text=(
                        f"Scoped package '{pkg}' found in JS bundle and "
                        "exists on public npm registry"
                    ),
                    raw_confidence=0.65,
                    severity="HIGH",
                    cvss=7.3,
                )
