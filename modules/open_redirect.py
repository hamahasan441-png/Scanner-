#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Open Redirect Module
Detects open redirect vulnerabilities by injecting redirect payloads
into parameters commonly used for URL redirection.
"""

import os
import sys
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Payloads, Colors


class OpenRedirectModule:
    """Open Redirect Testing Module"""

    REDIRECT_PARAMS = {
        'url', 'redirect', 'redirect_url', 'redirect_uri', 'return',
        'return_url', 'returnto', 'next', 'goto', 'rurl', 'dest',
        'destination', 'redir', 'redirect_to', 'continue', 'forward',
        'target', 'out', 'view', 'ref', 'callback', 'path',
    }

    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.name = "Open Redirect"

    def test(self, url: str, method: str, param: str, value: str):
        """Test a parameter for open redirect."""
        if param.lower() not in self.REDIRECT_PARAMS:
            return

        payloads = Payloads.OPEN_REDIRECT_PAYLOADS

        for payload in payloads:
            try:
                response = self.requester.request(
                    url, method, data={param: payload},
                    allow_redirects=False,
                )
                if not response:
                    continue

                # Check for redirect in Location header
                location = response.headers.get('Location', '')
                if self._is_open_redirect(location, payload):
                    from core.engine import Finding
                    finding = Finding(
                        technique="Open Redirect",
                        url=url,
                        param=param,
                        payload=payload,
                        evidence=f"Location: {location}",
                        severity='MEDIUM',
                        confidence=0.85,
                    )
                    self.engine.add_finding(finding)
                    return

                # Check for redirect via meta refresh or JavaScript
                if response.status_code == 200 and response.text:
                    body = response.text[:5000].lower()
                    if self._check_meta_redirect(body, payload):
                        from core.engine import Finding
                        finding = Finding(
                            technique="Open Redirect (Meta/JS)",
                            url=url,
                            param=param,
                            payload=payload,
                            evidence="Redirect payload reflected in page body",
                            severity='LOW',
                            confidence=0.6,
                        )
                        self.engine.add_finding(finding)
                        return

            except Exception as e:
                if self.engine.config.get('verbose'):
                    print(f"{Colors.error(f'Open redirect test error: {e}')}")

    def test_url(self, url: str):
        """URL-level open redirect test (not applicable)."""
        pass

    def _is_open_redirect(self, location, payload):
        """Check if the Location header redirects to an external domain."""
        if not location:
            return False
        payload_lower = payload.lower()
        location_lower = location.lower()

        # Direct match
        if payload_lower in location_lower:
            return True

        # Check for external domain in Location
        try:
            parsed = urlparse(location)
            if parsed.netloc and parsed.netloc not in ('', 'localhost', '127.0.0.1'):
                evil_domains = ['evil.com', 'attacker.com']
                return any(d in parsed.netloc.lower() for d in evil_domains)
        except Exception:
            pass

        return False

    def _check_meta_redirect(self, body, payload):
        """Check for meta refresh or JS redirect containing the payload."""
        payload_lower = payload.lower()
        return (
            (f'url={payload_lower}' in body) or
            (f"location='{payload_lower}'" in body) or
            (f'location="{payload_lower}"' in body) or
            (f'location.href="{payload_lower}"' in body) or
            (f"window.location='{payload_lower}'" in body)
        )
