#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v11.0 — API Versioning Abuse Module
=====================================================

Tests deprecated and unversioned API endpoints that may be less
protected than current versions:
  - Try v0, v1, v2 ... alongside the detected version
  - Test beta, staging, dev, internal prefixes
  - Check for security controls (auth, rate-limiting) missing on old versions
  - Test for endpoints available on /api/v1/ but removed from /api/v2/

Enabled with: ``--api-versioning``
"""

from __future__ import annotations

import re
import urllib.parse
from typing import List, Optional, Tuple

from modules.base import BaseModule


class APIVersioningModule(BaseModule):
    """API versioning abuse and deprecated endpoint detection."""

    name = "API Versioning Abuse"
    vuln_type = "api_versioning"

    # Common version path components
    VERSION_PREFIXES = [
        "v0", "v1", "v2", "v3", "v4", "v5",
        "v1.0", "v1.1", "v2.0", "v2.1",
        "beta", "alpha", "staging", "dev", "debug",
        "internal", "test", "legacy", "old", "deprecated",
        "2023", "2022", "2021",
    ]

    # Sensitive endpoints that may exist on old versions but not new
    SENSITIVE_PATHS = [
        "/admin", "/users", "/accounts", "/export",
        "/debug", "/config", "/settings",
        "/dump", "/backup", "/restore",
        "/swagger", "/api-docs", "/openapi.json",
        "/graphql", "/introspect",
    ]

    # API base path patterns
    API_BASE_PATTERNS = [
        r"(/api/v\d+[\d.]*)",
        r"(/v\d+[\d.]*)",
        r"(/rest/v\d+[\d.]*)",
        r"(/service/v\d+[\d.]*)",
    ]

    def test(self, url: str, method: str, param: str, value: str) -> None:
        """Per-parameter test (not primary for this module)."""
        pass

    def test_url(self, url: str) -> None:
        """Discover and test alternate API versions for this URL."""
        # Detect current version in URL
        current_version, base_url, suffix = self._extract_version(url)
        if current_version:
            self._test_version_variants(url, current_version, base_url, suffix)
        else:
            # No version detected — try adding common version prefixes
            self._test_unversioned_api(url)

    # ------------------------------------------------------------------
    # Core logic
    # ------------------------------------------------------------------

    def _extract_version(self, url: str) -> Tuple[Optional[str], str, str]:
        """Extract current version component from URL.

        Returns (version_string, base_before_version, suffix_after_version).
        """
        parsed = urllib.parse.urlparse(url)
        path = parsed.path

        for pattern in self.API_BASE_PATTERNS:
            m = re.search(pattern, path, re.IGNORECASE)
            if m:
                version_segment = m.group(1)
                idx = path.index(version_segment)
                base = f"{parsed.scheme}://{parsed.netloc}{path[:idx]}"
                suffix = path[idx + len(version_segment):]
                version = re.search(r"v?(\d[\d.]*|alpha|beta|staging|dev)", version_segment, re.I)
                return (
                    version_segment if version else None,
                    base,
                    suffix + ("?" + parsed.query if parsed.query else ""),
                )

        return None, f"{parsed.scheme}://{parsed.netloc}", parsed.path

    def _test_version_variants(
        self,
        original_url: str,
        current_version: str,
        base_url: str,
        suffix: str,
    ):
        """Test all version variants of a discovered versioned endpoint."""
        # Get baseline response for the current version
        baseline = self.requester.request(original_url, "GET")
        if not baseline:
            return
        baseline_status = baseline.status_code
        baseline_body = getattr(baseline, "text", "")[:500]

        for version in self.VERSION_PREFIXES:
            if version in current_version.lower():
                continue  # Skip current version
            test_url = f"{base_url}/{version}{suffix}"
            resp = self.requester.request(test_url, "GET")
            if not resp:
                continue

            # Interesting if old version returns 200 while current requires auth
            if resp.status_code == 200 and baseline_status in (401, 403, 404):
                body = getattr(resp, "text", "")
                self._emit_signal(
                    vuln_type="api_versioning",
                    technique=f"API Version Bypass — Auth bypass via {version}",
                    url=test_url,
                    method="GET",
                    param="",
                    payload=version,
                    evidence_text=(
                        f"Current version {current_version} returns HTTP {baseline_status}, "
                        f"but {version} returns 200 OK"
                    ),
                    raw_confidence=0.80,
                    severity="HIGH",
                    cvss=7.5,
                )

            # Interesting if old version exposes more data
            elif resp.status_code == 200 and baseline_status == 200:
                body = getattr(resp, "text", "")
                if len(body) > len(baseline_body) * 1.5:
                    self._emit_signal(
                        vuln_type="api_versioning",
                        technique=f"API Version Data Leak — {version} returns more data",
                        url=test_url,
                        method="GET",
                        param="",
                        payload=version,
                        evidence_text=(
                            f"Version {version} response is {len(body)} chars vs "
                            f"{len(baseline_body)} for current version"
                        ),
                        raw_confidence=0.60,
                        severity="MEDIUM",
                        cvss=5.3,
                    )

    def _test_unversioned_api(self, url: str):
        """Try adding version prefixes to an unversioned URL."""
        parsed = urllib.parse.urlparse(url)
        path = parsed.path

        # Check if this looks like an API endpoint
        if not any(seg in path.lower() for seg in ("/api/", "/rest/", "/service/")):
            return

        # Baseline
        baseline = self.requester.request(url, "GET")
        baseline_status = baseline.status_code if baseline else 404

        for version in ["v1", "v2", "beta", "internal", "debug"]:
            # Try inserting version before first /api/ path segment
            if "/api/" in path:
                test_path = path.replace("/api/", f"/api/{version}/", 1)
            else:
                test_path = "/" + version + path

            test_url = urllib.parse.urlunparse(parsed._replace(path=test_path))
            resp = self.requester.request(test_url, "GET")
            if not resp:
                continue

            if resp.status_code == 200 and baseline_status in (401, 403, 404):
                self._emit_signal(
                    vuln_type="api_versioning",
                    technique=f"Hidden API Version Discovered: {version}",
                    url=test_url,
                    method="GET",
                    param="",
                    payload=version,
                    evidence_text=f"Unversioned URL returns {baseline_status}, but /{version}/ returns 200",
                    raw_confidence=0.70,
                    severity="MEDIUM",
                    cvss=5.3,
                )

        # Test for Swagger/OpenAPI exposure on old versions
        for version in ["v1", "v2"]:
            for doc_path in ["/swagger.json", "/openapi.json", "/swagger-ui.html", "/api-docs"]:
                if "/api/" in path:
                    test_url = f"{parsed.scheme}://{parsed.netloc}/api/{version}{doc_path}"
                else:
                    test_url = f"{parsed.scheme}://{parsed.netloc}/{version}{doc_path}"
                resp = self.requester.request(test_url, "GET")
                if resp and resp.status_code == 200:
                    self._emit_signal(
                        vuln_type="api_versioning",
                        technique=f"API Documentation Exposed — /{version}{doc_path}",
                        url=test_url,
                        method="GET",
                        param="",
                        payload=doc_path,
                        evidence_text=f"API docs accessible at {test_url}",
                        raw_confidence=0.75,
                        severity="MEDIUM",
                        cvss=5.3,
                    )
