#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v10.0 - TargetSurface Pipeline Stage
======================================================

First-class surface discovery: aggregates endpoints from multiple
sources, canonicalizes and deduplicates them, then produces a stable
``TargetSurface`` with a deterministic ``surface_id`` hash.

Public API
----------
::

    from core.surface import build_target_surface

    surface = build_target_surface(config, target, requester)
    # surface.surface_id is a stable SHA-256 hex prefix
    # surface.endpoints are sorted and deduplicated

Surface sources (in precedence order)
--------------------------------------
1. Seed endpoints file (``config.seed_file``) – user-supplied, highest trust
2. robots.txt parsed paths
3. sitemap.xml parsed URLs
4. OpenAPI / Swagger spec detection
5. HTML crawler artifacts (links, forms, inputs)
6. HTTP redirect / Location header paths
7. Cookie paths
8. Static JS string extraction (no dynamic eval)

Canonicalization pipeline
--------------------------
For each raw URL discovered:
1. ``normalize_url()`` – lowercase scheme+host, strip default port
2. ``normalize_path_trailing_slash()`` – strip trailing slash (except root "/")
3. ``normalize_query_shape()`` – sort query params alphabetically
4. ``strip_tracking_params()`` – remove configurable noise params
5. ``endpoint_shape_key()`` – stable dedupe key: method+host+path+param-shape

Caps
----
``config.max_surface_endpoints`` (default 2000) prevents runaway crawl.
"""

from __future__ import annotations

import hashlib
import re
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import (
    parse_qs,
    urlencode,
    urlparse,
    urlunparse,
)

from core.models import (
    ScanConfig,
    SurfaceEndpoint,
    SurfaceParam,
    TargetSurface,
)

# Default tracking parameters to strip when canonicalizing URLs.
_DEFAULT_TRACKING_PARAMS: Set[str] = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "fbclid",
    "gclid",
    "msclkid",
    "mc_cid",
    "mc_eid",
    "_ga",
    "_gl",
    "ref",
    "source",
    "affiliate",
}

# Simple regex to find candidate API path strings in JS files.
# Matches single/double-quoted path-like strings starting with "/"
# e.g. '/api/v1/users', "/search"
_JS_PATH_PATTERN = re.compile(r"""['"](/(?:api|v\d|rest|service|endpoint)[^'"<>\s]{0,100})['"]""")


# ---------------------------------------------------------------------------
# URL Canonicalization helpers
# ---------------------------------------------------------------------------


def normalize_url(url: str) -> str:
    """Normalize a URL to a canonical form for deduplication.

    Steps:
    * Lowercase scheme and host.
    * Remove default ports (80 for http, 443 for https).
    * Decode unreserved percent-encoded characters.
    * Sort query parameters alphabetically (call normalize_query_shape).
    * Strip fragment.

    Returns the normalized URL string, or the original if parsing fails.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return url

    scheme = (parsed.scheme or "https").lower()
    netloc = (parsed.netloc or "").lower()

    # Strip default ports
    if scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]

    path = normalize_path_trailing_slash(parsed.path or "/")
    query = normalize_query_shape(parsed.query)

    return urlunparse((scheme, netloc, path, "", query, ""))


def normalize_path_trailing_slash(path: str) -> str:
    """Remove trailing slash except for the root path '/'."""
    if not path:
        return "/"
    if path != "/" and path.endswith("/"):
        return path.rstrip("/")
    return path


def normalize_query_shape(query_string: str, strip_params: Optional[Iterable[str]] = None) -> str:
    """Sort query parameters alphabetically and strip tracking params.

    Args:
        query_string: Raw query string (no leading ``?``).
        strip_params: Parameter names to remove.  Falls back to the
            module-level ``_DEFAULT_TRACKING_PARAMS`` set.

    Returns:
        Normalized, sorted query string.
    """
    if not query_string:
        return ""

    strip = set(strip_params) if strip_params is not None else _DEFAULT_TRACKING_PARAMS

    try:
        params = parse_qs(query_string, keep_blank_values=True)
    except Exception:
        return query_string

    # Remove tracking params (case-insensitive key match)
    filtered = {k: v for k, v in params.items() if k.lower() not in strip}

    # Sort keys, then re-encode
    sorted_pairs: List[Tuple[str, str]] = []
    for key in sorted(filtered.keys()):
        for val in sorted(filtered[key]):
            sorted_pairs.append((key, val))

    return urlencode(sorted_pairs)


def strip_tracking_params(url: str, extra_strip: Optional[Iterable[str]] = None) -> str:
    """Remove tracking/noise query parameters from a URL.

    Args:
        url: Full URL string.
        extra_strip: Additional parameter names to strip beyond defaults.

    Returns:
        URL with tracking params removed and remaining params sorted.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return url

    strip = set(_DEFAULT_TRACKING_PARAMS)
    if extra_strip:
        strip.update(extra_strip)

    new_query = normalize_query_shape(parsed.query, strip_params=strip)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", new_query, ""))


def endpoint_shape_key(method: str, url: str, params: List[SurfaceParam]) -> str:
    """Canonical shape key for endpoint deduplication.

    Two endpoints that share the same (method, host, path, param-set-shape)
    are considered duplicates regardless of concrete param values.

    Shape = method + netloc + normalized-path + sorted(location:name) for each param.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return f"{method.upper()}::{url}"

    path = normalize_path_trailing_slash(parsed.path or "/")
    netloc = (parsed.netloc or "").lower()
    param_sig = "|".join(sorted(p.shape_key() for p in params))
    return f"{method.upper()}:{netloc}:{path}:{param_sig}"


# ---------------------------------------------------------------------------
# Source collectors
# ---------------------------------------------------------------------------


def collect_from_crawler(crawler) -> List[Tuple[str, str, List[SurfaceParam]]]:
    """Extract (url, method, params) tuples from a crawler artifact.

    Compatible with ``utils.crawler.Crawler`` instances (uses
    ``visited``, ``forms``, ``parameters`` attributes).
    """
    results: List[Tuple[str, str, List[SurfaceParam]]] = []

    # Visited URLs (GET, no params from URL path)
    visited = getattr(crawler, "visited", set()) or set()
    for url in visited:
        results.append((url, "GET", _params_from_url(url)))

    # Forms
    forms = getattr(crawler, "forms", []) or []
    for form in forms:
        form_url = form.get("url") or form.get("action", "")
        if not form_url:
            continue
        method = (form.get("method") or "GET").upper()
        params = [
            SurfaceParam(
                name=inp.get("name", ""),
                value=inp.get("value", ""),
                location="form",
            )
            for inp in form.get("inputs", [])
            if inp.get("name")
        ]
        if form_url:
            results.append((form_url, method, params))

    return results


def collect_from_robots(robots_text: str, base_url: str) -> List[Tuple[str, str, List[SurfaceParam]]]:
    """Parse robots.txt and extract allowed/disallowed paths.

    Returns (url, "GET", []) tuples for every unique path found.
    """
    if not robots_text:
        return []

    try:
        parsed_base = urlparse(base_url)
        origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
    except Exception:
        origin = base_url.rstrip("/")

    results: List[Tuple[str, str, List[SurfaceParam]]] = []
    seen: Set[str] = set()

    for line in robots_text.splitlines():
        line = line.strip()
        lower = line.lower()
        if lower.startswith("allow:") or lower.startswith("disallow:"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                path = parts[1].strip()
                if path and path not in seen:
                    seen.add(path)
                    full_url = origin + path if path.startswith("/") else origin + "/" + path
                    results.append((full_url, "GET", []))

    return results


def collect_from_sitemap(sitemap_xml: str) -> List[Tuple[str, str, List[SurfaceParam]]]:
    """Parse sitemap.xml text and extract ``<loc>`` URLs."""
    if not sitemap_xml:
        return []

    results: List[Tuple[str, str, List[SurfaceParam]]] = []
    # Simple regex extraction — avoids xml.etree dependency issues on
    # targets with malformed sitemaps.
    for m in re.finditer(r"<loc>\s*(https?://[^<\s]+)\s*</loc>", sitemap_xml, re.IGNORECASE):
        url = m.group(1).strip()
        results.append((url, "GET", _params_from_url(url)))

    return results


def collect_from_js_static(js_text: str, base_url: str) -> List[Tuple[str, str, List[SurfaceParam]]]:
    """Extract candidate API path strings from static JS source.

    Uses a conservative regex — no dynamic evaluation.  Matches only
    strings that look like ``/api/...`` routes inside JS literals.
    """
    if not js_text:
        return []

    try:
        parsed_base = urlparse(base_url)
        origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
    except Exception:
        origin = base_url.rstrip("/")

    results: List[Tuple[str, str, List[SurfaceParam]]] = []
    seen: Set[str] = set()

    for m in _JS_PATH_PATTERN.finditer(js_text):
        path = m.group(1)
        if path and path not in seen:
            seen.add(path)
            full_url = origin + path
            results.append((full_url, "GET", _params_from_url(full_url)))

    return results


def collect_from_openapi(spec_dict: dict, base_url: str) -> List[Tuple[str, str, List[SurfaceParam]]]:
    """Extract endpoints from an OpenAPI 2 or 3 spec dict.

    Args:
        spec_dict: Parsed JSON/YAML spec.
        base_url: Used to build full URLs when spec lacks servers.

    Returns:
        List of (url, method, params) tuples.
    """
    if not spec_dict:
        return []

    results: List[Tuple[str, str, List[SurfaceParam]]] = []

    # Determine base path
    # OpenAPI 3: spec["servers"][0]["url"]
    # Swagger 2: spec["basePath"]
    servers = spec_dict.get("servers", [])
    if servers and isinstance(servers, list):
        api_base = servers[0].get("url", base_url).rstrip("/")
    else:
        base_path = spec_dict.get("basePath", "").rstrip("/")
        parsed_base = urlparse(base_url)
        host = spec_dict.get("host", parsed_base.netloc)
        scheme = (spec_dict.get("schemes") or ["https"])[0]
        api_base = f"{scheme}://{host}{base_path}"

    paths = spec_dict.get("paths", {})
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for http_method, operation in path_item.items():
            if http_method.lower() not in ("get", "post", "put", "patch", "delete", "head", "options"):
                continue
            if not isinstance(operation, dict):
                continue

            full_url = api_base + path
            params: List[SurfaceParam] = []

            for param_def in operation.get("parameters", []):
                if not isinstance(param_def, dict):
                    continue
                name = param_def.get("name", "")
                location = param_def.get("in", "query")
                if name:
                    params.append(SurfaceParam(name=name, value="", location=location))

            results.append((full_url, http_method.upper(), params))

    return results


def collect_from_seed_file(seed_file: str) -> List[Tuple[str, str, List[SurfaceParam]]]:
    """Load seed endpoints from a plain-text file.

    Each line must be either:
    * A full URL:  ``https://example.com/api/users``
    * A ``METHOD URL`` pair:  ``POST https://example.com/login``

    Blank lines and lines starting with ``#`` are ignored.
    """
    results: List[Tuple[str, str, List[SurfaceParam]]] = []
    try:
        with open(seed_file, encoding="utf-8") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2 and parts[0].upper() in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"):
                    method, url = parts[0].upper(), parts[1]
                else:
                    method, url = "GET", parts[0]
                results.append((url, method, _params_from_url(url)))
    except (OSError, IOError):
        pass
    return results


def collect_from_redirects(responses: list, base_url: str) -> List[Tuple[str, str, List[SurfaceParam]]]:
    """Extract redirect target URLs from a list of response objects.

    Accepts any response-like object with a ``headers`` dict attribute.
    """
    try:
        parsed_base = urlparse(base_url)
        origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
    except Exception:
        origin = base_url.rstrip("/")

    results: List[Tuple[str, str, List[SurfaceParam]]] = []
    for resp in responses or []:
        headers = getattr(resp, "headers", {}) or {}
        location = headers.get("Location") or headers.get("location", "")
        if location:
            if location.startswith("/"):
                location = origin + location
            if location.startswith("http"):
                results.append((location, "GET", _params_from_url(location)))

    return results


# ---------------------------------------------------------------------------
# Core builder
# ---------------------------------------------------------------------------


def build_target_surface(
    config: ScanConfig,
    target: str,
    *,
    crawler=None,
    robots_text: str = "",
    sitemap_text: str = "",
    openapi_spec: Optional[dict] = None,
    js_texts: Optional[List[str]] = None,
    responses: Optional[list] = None,
) -> TargetSurface:
    """Build a canonicalized, deduplicated ``TargetSurface``.

    Aggregates raw URL/endpoint data from multiple sources, applies the
    full canonicalization pipeline, deduplicates by ``endpoint_shape_key``,
    sorts endpoints deterministically, and computes the stable
    ``surface_id`` hash.

    Args:
        config:        ``ScanConfig`` for this scan (provides caps, strip list, seed file).
        target:        The canonical base target URL.
        crawler:       Optional crawler artifact (``utils.crawler.Crawler`` instance).
        robots_text:   Raw text from ``/robots.txt``.
        sitemap_text:  Raw text from ``/sitemap.xml``.
        openapi_spec:  Parsed OpenAPI/Swagger JSON dict (optional).
        js_texts:      List of raw JS source strings for static path extraction.
        responses:     HTTP response objects used for redirect extraction.

    Returns:
        A fully-built ``TargetSurface`` with a stable ``surface_id``.
    """
    max_eps = config.max_surface_endpoints
    strip_params = set(config.strip_tracking_params)

    # Collect raw tuples from all sources
    raw: List[Tuple[str, str, List[SurfaceParam]]] = []

    # 1. Seed file (highest trust)
    if config.seed_file:
        raw.extend(collect_from_seed_file(config.seed_file))

    # 2. robots.txt
    if robots_text:
        raw.extend(collect_from_robots(robots_text, target))

    # 3. sitemap.xml
    if sitemap_text:
        raw.extend(collect_from_sitemap(sitemap_text))

    # 4. OpenAPI / Swagger
    if openapi_spec:
        raw.extend(collect_from_openapi(openapi_spec, target))

    # 5. Crawler artifacts
    if crawler is not None:
        raw.extend(collect_from_crawler(crawler))

    # 6. Redirect targets
    if responses:
        raw.extend(collect_from_redirects(responses, target))

    # 7. Static JS strings
    for js in (js_texts or []):
        raw.extend(collect_from_js_static(js, target))

    # Always include the base target itself
    raw.append((target, "GET", _params_from_url(target)))

    # Canonicalize + deduplicate
    seen_shape_keys: Dict[str, SurfaceEndpoint] = {}

    for url, method, params in raw:
        if len(seen_shape_keys) >= max_eps:
            break
        try:
            canon_url = normalize_url(url)
            canon_url = strip_tracking_params(canon_url, extra_strip=strip_params)
        except Exception:
            canon_url = url

        if not canon_url:
            continue

        ep = SurfaceEndpoint(
            url=canon_url,
            method=method.upper(),
            params=params,
            discovery_source=_infer_source(url, robots_text, sitemap_text, openapi_spec, crawler),
        )
        key = endpoint_shape_key(ep.method, ep.url, ep.params)

        if key not in seen_shape_keys:
            seen_shape_keys[key] = ep
        else:
            # Merge params from duplicate into existing (keep unique param names)
            existing = seen_shape_keys[key]
            existing_names = {p.shape_key() for p in existing.params}
            for p in ep.params:
                if p.shape_key() not in existing_names:
                    existing.params.append(p)
                    existing_names.add(p.shape_key())

    # Sort endpoints deterministically: (method, netloc, path, param_sig)
    endpoints = sorted(
        seen_shape_keys.values(),
        key=lambda e: endpoint_shape_key(e.method, e.url, e.params),
    )

    surface = TargetSurface(target=normalize_url(target), endpoints=endpoints)
    surface.compute_id()
    return surface


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _params_from_url(url: str) -> List[SurfaceParam]:
    """Extract query parameters from a URL as SurfaceParam list."""
    try:
        parsed = urlparse(url)
        if not parsed.query:
            return []
        qs = parse_qs(parsed.query, keep_blank_values=True)
        return [
            SurfaceParam(name=k, value=(v[0] if v else ""), location="query")
            for k in sorted(qs.keys())
            for v in [qs[k]]
        ]
    except Exception:
        return []


def _infer_source(
    url: str,
    robots_text: str,
    sitemap_text: str,
    openapi_spec: Optional[dict],
    crawler,
) -> str:
    """Best-effort guess at a URL's discovery source (for metadata only)."""
    if openapi_spec and url:
        return "openapi"
    if sitemap_text and "sitemap" in url.lower():
        return "sitemap"
    if robots_text and ("robots" in url.lower() or "disallow" in url.lower()):
        return "robots"
    if crawler is not None:
        visited = getattr(crawler, "visited", set()) or set()
        if url in visited:
            return "crawler"
    return "crawler"
