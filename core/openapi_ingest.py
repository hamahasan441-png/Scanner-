#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — OpenAPI / Swagger ingester

Reads an OpenAPI 3.x or Swagger 2.0 spec (JSON or YAML) and expands
every documented ``path × method × parameter`` into ``SeedRequest``s
the scanner can enumerate. Multiplies coverage on any target that
publishes its spec (public API docs, /openapi.json, /swagger.json).

Supported:
    * Path parameters — substituted with a probe value ("1")
    * Query parameters — added with a probe value
    * Header parameters — added
    * Request bodies — application/json and form-urlencoded get a
      minimal payload generated from the schema
    * Security schemes — Bearer / API-Key headers filled from
      ``auth={...}`` (e.g. auth={"bearer_token":"...","api_key":"..."})
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin

from core.har_ingest import SeedRequest


def _load_spec(path: str) -> dict:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    text_stripped = text.lstrip()
    if text_stripped.startswith("{"):
        return json.loads(text)
    # YAML fallback (best-effort, PyYAML if available).
    try:
        import yaml  # type: ignore[import-untyped]
    except Exception as exc:
        raise RuntimeError("YAML spec but PyYAML not installed") from exc
    return yaml.safe_load(text)


def _base_url(spec: dict, override: Optional[str] = None) -> str:
    if override:
        return override.rstrip("/")
    # OpenAPI 3.x
    servers = spec.get("servers") or []
    if servers and isinstance(servers[0], dict) and servers[0].get("url"):
        return servers[0]["url"].rstrip("/")
    # Swagger 2.0
    host = spec.get("host") or "example.com"
    scheme = (spec.get("schemes") or ["https"])[0]
    base_path = spec.get("basePath") or ""
    return f"{scheme}://{host}{base_path}".rstrip("/")


def _example_for_schema(schema: dict) -> Any:
    """Very small schema-to-example. Enough to get past 'body required'
    server-side validation without matching the schema exactly."""
    if not schema:
        return "probe"
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    t = schema.get("type")
    if t == "integer":
        return 1
    if t == "number":
        return 1.0
    if t == "boolean":
        return True
    if t == "array":
        return [_example_for_schema(schema.get("items") or {})]
    if t == "object":
        props = schema.get("properties") or {}
        required = schema.get("required") or []
        out: dict[str, Any] = {}
        for name, sub in props.items():
            if required and name not in required and len(out) >= 3:
                continue
            out[name] = _example_for_schema(sub)
        return out or {"probe": "probe"}
    return "probe"


def _auth_headers(spec: dict, auth: dict[str, str]) -> dict[str, str]:
    if not auth:
        return {}
    hdrs: dict[str, str] = {}
    if auth.get("bearer_token"):
        hdrs["Authorization"] = f"Bearer {auth['bearer_token']}"
    if auth.get("api_key"):
        # Try to place API key according to security schemes.
        secs = spec.get("components", {}).get("securitySchemes") or spec.get("securityDefinitions") or {}
        placed = False
        for sec in secs.values():
            if sec.get("type") == "apiKey" and sec.get("in") == "header" and sec.get("name"):
                hdrs[sec["name"]] = auth["api_key"]
                placed = True
                break
        if not placed:
            hdrs["X-API-Key"] = auth["api_key"]
    return hdrs


def _expand_operation(
    base: str,
    path: str,
    method: str,
    op: dict,
    spec_params: list[dict],
    auth: dict[str, str],
    spec: dict,
) -> SeedRequest:
    resolved_path = path
    query: dict[str, str] = {}
    headers: dict[str, str] = dict(_auth_headers(spec, auth))

    all_params = list(spec_params) + list(op.get("parameters") or [])
    for p in all_params:
        if not isinstance(p, dict):
            continue
        name = p.get("name")
        loc = p.get("in")
        if not name or not loc:
            continue
        example = _example_for_schema(p.get("schema") or {})
        if not isinstance(example, (str, int, float, bool)):
            example = "probe"
        if loc == "path":
            resolved_path = resolved_path.replace("{" + name + "}", str(example))
        elif loc == "query":
            query[name] = str(example)
        elif loc == "header":
            headers[name] = str(example)

    url = urljoin(base + "/", resolved_path.lstrip("/"))
    if query:
        from urllib.parse import urlencode
        url += ("&" if "?" in url else "?") + urlencode(query)

    body: Optional[str] = None
    ct = ""
    rb = op.get("requestBody") or {}
    content = rb.get("content") or {}
    if "application/json" in content:
        body = json.dumps(_example_for_schema(content["application/json"].get("schema") or {}))
        ct = "application/json"
    elif "application/x-www-form-urlencoded" in content:
        from urllib.parse import urlencode
        example = _example_for_schema(content["application/x-www-form-urlencoded"].get("schema") or {})
        if isinstance(example, dict):
            body = urlencode({k: str(v) for k, v in example.items()})
            ct = "application/x-www-form-urlencoded"

    if ct and "Content-Type" not in headers:
        headers["Content-Type"] = ct

    return SeedRequest(
        url=url,
        method=method.upper(),
        headers=headers,
        params=query,
        body=body,
        content_type=ct,
        source="openapi",
    )


_HTTP_METHODS = ("get", "post", "put", "patch", "delete", "options", "head")


def ingest(
    path: str,
    *,
    base_url: Optional[str] = None,
    auth: Optional[dict[str, str]] = None,
) -> list[SeedRequest]:
    """Return a SeedRequest per (path, method) operation in the spec."""
    spec = _load_spec(path)
    base = _base_url(spec, base_url)
    auth = auth or {}
    seeds: list[SeedRequest] = []
    for p, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        spec_params = list(item.get("parameters") or [])
        for method in _HTTP_METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            try:
                seeds.append(_expand_operation(
                    base, p, method, op, spec_params, auth, spec,
                ))
            except Exception:
                continue
    return seeds
