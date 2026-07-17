#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Web Cache Poisoning Module

Detects web cache poisoning vulnerabilities including:
- Unkeyed headers (X-Forwarded-Host, X-Original-URL, X-Rewrite-URL, etc.)
- Unkeyed query parameters
- Fat GET requests (body in GET requests)
- Host header cache poisoning
- Port-based cache key issues
"""

from urllib.parse import urlparse
import time
import hashlib

from config import Payloads
from modules.base import BaseModule


class CachePoisoningModule(BaseModule):
    """Web Cache Poisoning detection module."""

    name = "Cache Poisoning"
    vuln_type = "cache_poisoning"

    # Headers that indicate caching
    CACHE_INDICATORS = [
        "Age",
        "X-Cache",
        "CF-Cache-Status",
        "X-Varnish",
        "X-Cache-Hits",
        "X-Proxy-Cache",
        "X-Drupal-Cache",
        "X-Rack-Cache",
        "X-Cache-Status",
        "Fastly-Cache-Status",
    ]

    # Cache hit values that indicate a cached response
    CACHE_HIT_VALUES = [
        "HIT",
        "hit",
        "TCP_HIT",
        "MISS, HIT",
        "cached",
    ]

    def __init__(self, engine):
        super().__init__(engine)

    def test(self, url: str, method: str, param: str, value: str) -> None:
        """Test for cache poisoning (URL-level check)."""
        pass  # Cache poisoning is tested at URL level

    def test_url(self, url: str) -> None:
        """Run all cache poisoning checks against the target URL."""
        # First check if the target uses caching
        if not self._detect_caching(url):
            return

        self._test_unkeyed_headers(url)
        self._test_unkeyed_query_params(url)
        self._test_fat_get(url)
        self._test_host_header_poisoning(url)
        self._test_port_based_poisoning(url)

    def _detect_caching(self, url):
        """Detect whether the target uses caching based on response headers."""
        try:
            response = self.requester.request(url, "GET")
            if not response:
                return False

            for header in self.CACHE_INDICATORS:
                if header.lower() in [h.lower() for h in response.headers.keys()]:
                    return True

            # Send same request twice and check for Age header increase
            time.sleep(0.5)
            response2 = self.requester.request(url, "GET")
            if response2:
                age = response2.headers.get("Age", "")
                if age and age.isdigit() and int(age) > 0:
                    return True

            return False
        except Exception:
            return False

    def _is_cache_hit(self, response):
        """Check if a response was served from cache."""
        if not response:
            return False
        for header in self.CACHE_INDICATORS:
            value = response.headers.get(header, "")
            if value:
                for hit_val in self.CACHE_HIT_VALUES:
                    if hit_val.lower() in value.lower():
                        return True
        age = response.headers.get("Age", "")
        if age and age.isdigit() and int(age) > 0:
            return True
        return False

    def _test_unkeyed_headers(self, url):
        """Test for cache poisoning via unkeyed headers."""
        poisoning_headers = getattr(Payloads, "CACHE_POISONING_HEADERS", [])
        if not poisoning_headers:
            poisoning_headers = [
                "X-Forwarded-Host",
                "X-Original-URL",
                "X-Rewrite-URL",
                "X-Forwarded-Scheme",
                "X-Forwarded-Proto",
                "X-Host",
                "X-Forwarded-Server",
                "X-HTTP-Method-Override",
            ]

        canary = "atomic-cache-poison-{}".format(
            hashlib.md5(url.encode(), usedforsecurity=False).hexdigest()[:8]
        )

        for header_name in poisoning_headers:
            try:
                # Add cache-buster to get a fresh cache entry
                cache_buster = f"cb={int(time.time())}"
                busted_url = self._add_param(url, cache_buster)

                # First request: poison the cache with our header
                poison_headers = {header_name: canary}
                resp1 = self.requester.request(busted_url, "GET", headers=poison_headers)
                if not resp1:
                    continue

                # Check if our canary is reflected in the response
                if canary not in resp1.text:
                    continue

                # Second request: without the header, check if cached
                time.sleep(0.3)
                resp2 = self.requester.request(busted_url, "GET")
                if not resp2:
                    continue

                # If canary appears in the non-poisoned request, cache is poisoned
                if canary in resp2.text or self._is_cache_hit(resp2):
                    self._emit_signal(
                        vuln_type="cache_poisoning",
                        technique=f"Web Cache Poisoning (Unkeyed Header: {header_name})",
                        url=url,
                        method="GET",
                        param=header_name,
                        payload=f"{header_name}: {canary}",
                        evidence_text=f"Canary '{canary}' reflected in cached response",
                        raw_confidence=0.85,
                        severity="HIGH",
                        cvss=7.5,
                    )
                    break  # One proof per URL is sufficient

            except Exception:
                continue

    def _test_unkeyed_query_params(self, url):
        """Test for cache poisoning via unkeyed query parameters."""
        canary = "atomic-qp-{}".format(
            hashlib.md5(url.encode(), usedforsecurity=False).hexdigest()[:8]
        )
        test_params = ["utm_source", "utm_content", "utm_medium", "fbclid", "_ga", "callback"]

        for param_name in test_params:
            try:
                # Add test param with canary
                poisoned_url = self._add_param(url, f"{param_name}={canary}")

                resp1 = self.requester.request(poisoned_url, "GET")
                if not resp1 or canary not in resp1.text:
                    continue

                # Request original URL to see if canary is cached
                time.sleep(0.3)
                resp2 = self.requester.request(url, "GET")
                if resp2 and canary in resp2.text:
                    self._emit_signal(
                        vuln_type="cache_poisoning",
                        technique=f"Web Cache Poisoning (Unkeyed Query Param: {param_name})",
                        url=url,
                        method="GET",
                        param=param_name,
                        payload=f"{param_name}={canary}",
                        evidence_text="Canary from unkeyed param reflected in cached response",
                        raw_confidence=0.80,
                        severity="HIGH",
                        cvss=7.5,
                    )
                    break

            except Exception:
                continue

    def _test_fat_get(self, url):
        """Test for cache poisoning via fat GET requests (body in GET)."""
        canary = "atomic-fat-{}".format(
            hashlib.md5(url.encode(), usedforsecurity=False).hexdigest()[:8]
        )

        try:
            # Send a GET request with a body
            body_data = f"param={canary}"
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            resp1 = self.requester.request(
                url, "GET", data=body_data, headers=headers
            )
            if not resp1 or canary not in resp1.text:
                return

            # Check if cached response includes the body-injected content
            time.sleep(0.3)
            resp2 = self.requester.request(url, "GET")
            if resp2 and canary in resp2.text:
                self._emit_signal(
                    vuln_type="cache_poisoning",
                    technique="Web Cache Poisoning (Fat GET Request)",
                    url=url,
                    method="GET",
                    param="body",
                    payload=body_data,
                    evidence_text="Body content from GET request reflected in cached response",
                    raw_confidence=0.80,
                    severity="HIGH",
                    cvss=7.5,
                )

        except Exception:
            pass

    def _test_host_header_poisoning(self, url):
        """Test for cache poisoning via Host header manipulation."""
        canary_host = "atomic-host-poison.evil.com"

        try:
            cache_buster = f"hcb={int(time.time())}"
            busted_url = self._add_param(url, cache_buster)

            # Send request with poisoned Host header
            headers = {"Host": canary_host}
            resp1 = self.requester.request(busted_url, "GET", headers=headers)
            if not resp1:
                return

            if canary_host not in resp1.text:
                return

            # Check if the poisoned host persists in cache
            time.sleep(0.3)
            resp2 = self.requester.request(busted_url, "GET")
            if resp2 and canary_host in resp2.text:
                self._emit_signal(
                    vuln_type="cache_poisoning",
                    technique="Web Cache Poisoning (Host Header)",
                    url=url,
                    method="GET",
                    param="Host",
                    payload=f"Host: {canary_host}",
                    evidence_text=f"Poisoned host '{canary_host}' in cached response",
                    raw_confidence=0.85,
                    severity="HIGH",
                    cvss=7.5,
                )

        except Exception:
            pass

    def _test_port_based_poisoning(self, url):
        """Test for cache poisoning via port injection in Host header."""
        parsed = urlparse(url)
        original_host = parsed.hostname or ""
        canary_port = "9999"

        try:
            cache_buster = f"pcb={int(time.time())}"
            busted_url = self._add_param(url, cache_buster)

            # Send request with port appended to Host
            poisoned_host = f"{original_host}:{canary_port}"
            headers = {"Host": poisoned_host}
            resp1 = self.requester.request(busted_url, "GET", headers=headers)
            if not resp1:
                return

            if f":{canary_port}" not in resp1.text:
                return

            # Check if the poisoned port persists
            time.sleep(0.3)
            resp2 = self.requester.request(busted_url, "GET")
            if resp2 and f":{canary_port}" in resp2.text:
                self._emit_signal(
                    vuln_type="cache_poisoning",
                    technique="Web Cache Poisoning (Port-Based Key Issue)",
                    url=url,
                    method="GET",
                    param="Host",
                    payload=f"Host: {poisoned_host}",
                    evidence_text=f"Port '{canary_port}' from Host header persists in cache",
                    raw_confidence=0.75,
                    severity="MEDIUM",
                    cvss=6.5,
                )

        except Exception:
            pass

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _add_param(url, param_str):
        """Add a query parameter string to a URL."""
        separator = "&" if "?" in url else "?"
        return url + separator + param_str
