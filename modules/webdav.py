#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - WebDAV Module
WebDAV detection, PUT method, MOVE, COPY, PROPFIND enumeration.
"""
from config import Colors
from modules.base import BaseModule


class WebDAVModule(BaseModule):
    """WebDAV detection and attack module."""

    name = "WebDAV"
    vuln_type = "webdav"

    def test_url(self, url):
        self._test_webdav_options(url)
        self._test_webdav_put(url)
        self._test_webdav_propfind(url)

    def test(self, url, method, param, value):
        pass

    def _test_webdav_options(self, url):
        """Check for WebDAV methods via OPTIONS."""
        try:
            resp = self.requester.request(url, "OPTIONS")
            if not resp:
                return
            allow = resp.headers.get("Allow", "") or resp.headers.get("MS-Author-Via", "")
            dav = resp.headers.get("DAV", "")
            webdav_methods = ["PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"]
            found = [m for m in webdav_methods if m in allow.upper()]
            if found or dav:
                self.engine.add_finding(self._finding(
                    technique="WebDAV Enabled",
                    url=url,
                    severity="MEDIUM",
                    confidence=0.9,
                    param="OPTIONS",
                    payload="OPTIONS request",
                    evidence=f"WebDAV methods: {', '.join(found) or dav}. Allow: {allow[:200]}",
                ))
        except Exception:
            pass

    def _test_webdav_put(self, url):
        """Test if PUT method is allowed."""
        try:
            import uuid
            test_file = f"atomic_test_{uuid.uuid4().hex[:8]}.txt"
            from urllib.parse import urlparse, urljoin
            test_url = urljoin(url, test_file)
            resp = self.requester.request(test_url, "PUT", data=b"atomic_test")
            if resp and resp.status_code in (200, 201, 204):
                self.engine.add_finding(self._finding(
                    technique="WebDAV PUT Allowed",
                    url=url,
                    severity="CRITICAL",
                    confidence=0.8,
                    param="PUT",
                    payload=f"PUT {test_file}",
                    evidence=f"PUT method accepted, file created: {test_url}",
                ))
        except Exception:
            pass

    def _test_webdav_propfind(self, url):
        """Test PROPFIND for directory listing."""
        try:
            headers = {"Depth": "1"}
            resp = self.requester.request(url, "PROPFIND", headers=headers)
            if resp and resp.status_code == 207:  # Multi-Status
                self.engine.add_finding(self._finding(
                    technique="WebDAV Directory Listing (PROPFIND)",
                    url=url,
                    severity="MEDIUM",
                    confidence=0.85,
                    param="PROPFIND",
                    payload="PROPFIND Depth: 1",
                    evidence=f"PROPFIND returned 207 Multi-Status: {resp.text[:300]}",
                ))
        except Exception:
            pass

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
