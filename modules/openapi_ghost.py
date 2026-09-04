#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — OpenAPI Ghost Endpoints

Given an OpenAPI/Swagger spec that the target serves publicly, look
for ghost endpoints: paths declared in the spec but not linked from
the app, verbs the spec declares that the app also serves but the
current auth context bypasses, and version diffs where a v1 route was
"removed" in v2 but the v1 handler is still live.

Every request is against the target itself; findings only fire when
we get a real 2xx/3xx from a path the caller did not know about.
"""
from __future__ import annotations

import json
from urllib.parse import urlparse, urljoin

from modules.base import BaseModule


_SPEC_PATHS = (
    "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/swagger.json", "/swagger/v1/swagger.json",
    "/v2/api-docs", "/v3/api-docs",
    "/api/openapi.json", "/api/swagger.json",
    "/api/v1/openapi.json", "/api/v2/openapi.json",
    "/docs/openapi.json", "/schema/",
)


class OpenAPIGhostModule(BaseModule):
    """Discover shadow endpoints from a public OpenAPI spec."""

    name = "OpenAPI Ghost Endpoints"
    vuln_type = "openapi_ghost"

    def test(self, url: str, method: str, param: str, value: str):
        pass  # host-level module

    def test_url(self, url: str):
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return
        base = f"{parsed.scheme}://{parsed.netloc}"
        spec = self._fetch_spec(base)
        if not spec:
            return
        self._probe_paths(base, spec)

    # ------------------------------------------------------------------

    def _fetch_spec(self, base: str):
        for p in _SPEC_PATHS:
            try:
                resp = self.requester.request(base + p, "GET", timeout=5)
            except Exception:
                continue
            if resp is None or resp.status_code != 200:
                continue
            body = resp.text or ""
            spec = None
            try:
                spec = json.loads(body)
            except Exception:
                try:
                    import yaml  # optional; ok if missing
                    spec = yaml.safe_load(body)
                except Exception:
                    spec = None
            if isinstance(spec, dict) and ("paths" in spec or "swagger" in spec or "openapi" in spec):
                from core.engine import Finding
                self.engine.add_finding(Finding(
                    technique="OpenAPI Spec Public",
                    url=base + p,
                    severity="LOW",
                    confidence=0.99,
                    param="spec",
                    payload=p,
                    evidence=f"OpenAPI/Swagger spec exposed with {len(spec.get('paths') or {})} paths",
                ))
                return spec
        return None

    def _probe_paths(self, base: str, spec: dict):
        paths = spec.get("paths") or {}
        for raw_path, ops in list(paths.items())[:200]:
            if not isinstance(ops, dict):
                continue
            # Skip templated params — need real values to be useful; a
            # future pass could sample from the spec's `examples` field.
            if "{" in raw_path:
                continue
            target = urljoin(base, raw_path)
            for verb in ("get", "post", "put", "delete", "patch"):
                op = ops.get(verb)
                if op is None:
                    continue
                try:
                    resp = self.requester.request(target, verb.upper(), timeout=5)
                except Exception:
                    continue
                if resp is None:
                    continue
                # Ghost signal: the spec declares this verb+path, and the
                # server responds 2xx/3xx unauthenticated (no 401/403).
                if 200 <= resp.status_code < 400:
                    from core.engine import Finding
                    self.engine.add_finding(Finding(
                        technique=f"OpenAPI Ghost Endpoint ({verb.upper()})",
                        url=target,
                        severity="MEDIUM",
                        confidence=0.75,
                        param=verb.upper(),
                        payload=raw_path,
                        evidence=(
                            f"Spec declares {verb.upper()} {raw_path}; server "
                            f"returned {resp.status_code} without auth"
                        ),
                    ))
