#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Open Redirect Module
Detects open redirect vulnerabilities by injecting redirect payloads
into parameters commonly used for URL redirection.
"""

from urllib.parse import urlparse


from config import Payloads, Colors


class OpenRedirectModule:
    """Open Redirect Testing Module"""

    REDIRECT_PARAMS = {
        "url",
        "redirect",
        "redirect_url",
        "redirect_uri",
        "return",
        "return_url",
        "returnto",
        "next",
        "goto",
        "rurl",
        "dest",
        "destination",
        "redir",
        "redirect_to",
        "continue",
        "forward",
        "target",
        "out",
        "view",
        "ref",
        "callback",
        "path",
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
                    url,
                    method,
                    data={param: payload},
                    allow_redirects=False,
                )
                if not response:
                    continue

                # Check for redirect in Location header
                location = response.headers.get("Location", "")
                if self._is_open_redirect(location, payload):
                    from core.engine import Finding

                    finding = Finding(
                        technique="Open Redirect",
                        url=url,
                        param=param,
                        payload=payload,
                        evidence=f"Location: {location}",
                        severity="MEDIUM",
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
                            severity="LOW",
                            confidence=0.6,
                        )
                        self.engine.add_finding(finding)
                        return

            except Exception as e:
                if self.engine.config.get("verbose"):
                    print(f"{Colors.error(f'Open redirect test error: {e}')}")

    def test_url(self, url: str):
        """URL-level open redirect test (not applicable)."""

    def _is_open_redirect(self, location, payload):
        """Check if the Location header actually redirects to the payload domain."""
        if not location:
            return False

        # Parse the Location header URL - only flag if the redirect target IS the payload
        try:
            parsed_location = urlparse(location)
            parsed_payload = urlparse(payload)

            # The Location header's hostname must match the payload's hostname
            if parsed_location.netloc and parsed_payload.netloc:
                loc_host = parsed_location.netloc.lower()
                payload_host = parsed_payload.netloc.lower()
                # Check if location redirects TO the payload domain (not just contains it as a parameter)
                if loc_host == payload_host:
                    return True
                # Also catch subdomains of the payload domain
                if payload_host and loc_host.endswith("." + payload_host):
                    return True
        except Exception:
            pass

        return False

    def _check_meta_redirect(self, body, payload):
        """Check for meta refresh or JS redirect containing the payload."""
        payload_lower = payload.lower()
        return (
            (f"url={payload_lower}" in body)
            or (f"location='{payload_lower}'" in body)
            or (f'location="{payload_lower}"' in body)
            or (f'location.href="{payload_lower}"' in body)
            or (f"window.location='{payload_lower}'" in body)
        )
