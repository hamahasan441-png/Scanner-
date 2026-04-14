#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v10.0 - ULTIMATE EDITION
Phase 8 — Vulnerability Scan Worker Pool

Dispatches scan items through a multi-gate pipeline:
  Gate 0: Pre-scan triage (skip static, structural dedup)
  Gate 1: Baseline capture (DifferentialEngine) — parallelized
  Gate 2: Surface mapping (injection points)
  Workers A-E: Injection / Auth / BizLogic / Misconfig / Crypto
  Concurrent dispatch: Worker categories run in parallel via ThreadPoolExecutor

Usage:
    pool = ScanWorkerPool(engine)
    raw_findings = pool.run(scan_queue)
"""

import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from config import Colors


# ── Static asset patterns for Gate 0 ───────────────────────────────────

STATIC_EXTENSIONS = {
    '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.bmp', '.webp',
    '.css', '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv',
    '.pdf', '.zip', '.gz', '.tar', '.rar',
    '.js',  # JS files are static but may be scanned for DOM XSS
}

# Worker categories and their module mappings
WORKER_MODULE_MAP = {
    'injection': ['sqli', 'xss', 'ssti', 'ssrf', 'cmdi', 'lfi', 'xxe', 'nosql'],
    'auth': ['idor', 'jwt', 'brute_force'],
    'bizlogic': ['race_condition', 'upload', 'deserialization'],
    'misconfig': ['cors', 'crlf', 'hpp', 'open_redirect', 'graphql', 'proto_pollution', 'websocket'],
    'cloud': ['cloud_scan', 'osint'],
    'crypto': [],  # Handled inline (TLS, cookie, rate limiting checks)
}

# Injection surface types
SURFACE_TYPES = ['query_param', 'post_body', 'json_body', 'header', 'cookie', 'path_segment']


# ── DifferentialEngine ─────────────────────────────────────────────────

class DifferentialEngine:
    """Gate 1 — Baseline capture and differential analysis.

    Sends unmodified + invalid-param requests to establish baseline,
    then all subsequent checks diff against the baseline.
    """

    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self._baselines: Dict[str, Dict] = {}

    def set_baseline(self, url: str, method: str, param: str, value: str) -> Dict:
        """Capture baseline response for a URL+param combination."""
        key = f"{method}:{url}:{param}"
        if key in self._baselines:
            return self._baselines[key]

        baseline = {
            'status': None,
            'body_length': 0,
            'response_time': 0.0,
            'error_status': None,
            'error_length': 0,
            'headers': {},
        }

        # Normal request
        try:
            start = time.time()
            resp = self.requester.request(url, method, data={param: value} if param else None)
            elapsed = time.time() - start
            if resp:
                baseline['status'] = resp.status_code
                baseline['body_length'] = len(resp.text) if hasattr(resp, 'text') else 0
                baseline['response_time'] = elapsed
                baseline['headers'] = dict(resp.headers) if hasattr(resp, 'headers') else {}
        except Exception:
            pass

        # Error request (invalid param value)
        try:
            error_data = {param: 'ATOMIC_INVALID_' + param} if param else None
            resp = self.requester.request(url, method, data=error_data)
            if resp:
                baseline['error_status'] = resp.status_code
                baseline['error_length'] = len(resp.text) if hasattr(resp, 'text') else 0
        except Exception:
            pass

        self._baselines[key] = baseline
        return baseline

    def diff(self, baseline: Dict, response) -> Dict:
        """Compare a test response against the baseline."""
        if response is None:
            return {'status_diff': True, 'length_diff': 0, 'time_diff': 0}

        resp_len = len(response.text) if hasattr(response, 'text') else 0
        return {
            'status_diff': response.status_code != baseline.get('status'),
            'length_diff': resp_len - baseline.get('body_length', 0),
            'length_ratio': abs(resp_len - baseline.get('body_length', 0)) / max(baseline.get('body_length', 1), 1),
            'time_diff': 0,  # caller should measure
        }


# ── InjectionSurface ──────────────────────────────────────────────────

@dataclass
class InjectionSurface:
    """A single injection point on a scan item."""
    surface_type: str = 'query_param'  # query_param, post_body, json_body, header, cookie, path_segment
    name: str = ''
    value: str = ''
    weight: float = 0.5

    def to_dict(self) -> Dict:
        return {
            'type': self.surface_type,
            'name': self.name,
            'weight': round(self.weight, 3),
        }


class SurfaceMapper:
    """Gate 2 — Map all injection surfaces for a scan item."""

    # High-weight header injection targets
    INJECTABLE_HEADERS = [
        ('X-Forwarded-For', 0.7),
        ('Referer', 0.6),
        ('User-Agent', 0.4),
        ('X-Forwarded-Host', 0.6),
        ('X-Original-URL', 0.7),
        ('X-Rewrite-URL', 0.7),
    ]

    @classmethod
    def map_surfaces(cls, scan_item) -> List[InjectionSurface]:
        """Extract all injection surfaces from a scan item."""
        surfaces = []

        # Query parameter
        if scan_item.param:
            surfaces.append(InjectionSurface(
                surface_type='query_param',
                name=scan_item.param,
                value=scan_item.value,
                weight=scan_item.param_context_weight,
            ))

        # URL path segments (for path traversal, IDOR)
        parsed = urlparse(scan_item.url)
        path_segments = [s for s in parsed.path.split('/') if s]
        for i, seg in enumerate(path_segments):
            if re.match(r'^\d+$', seg):  # Numeric segment → likely ID
                surfaces.append(InjectionSurface(
                    surface_type='path_segment',
                    name=f'path[{i}]',
                    value=seg,
                    weight=0.8,
                ))

        # HTTP headers
        for header_name, weight in cls.INJECTABLE_HEADERS:
            surfaces.append(InjectionSurface(
                surface_type='header',
                name=header_name,
                value='',
                weight=weight,
            ))

        # Sort by weight descending
        surfaces.sort(key=lambda s: s.weight, reverse=True)
        return surfaces


# ── ScanWorkerPool ─────────────────────────────────────────────────────

# Default parallel worker threads for baseline capture and worker dispatch
_DEFAULT_BASELINE_WORKERS = 10
_DEFAULT_DISPATCH_WORKERS = 4


class ScanWorkerPool:
    """Phase 8 — Dispatch scan items through gate pipeline and workers.

    Scalability improvements over sequential execution:
    - Parallel baseline capture via ThreadPoolExecutor (10x Gate 1 speedup)
    - Concurrent worker category dispatch (Workers A-E run in parallel)
    - Batch processing with configurable concurrency
    """

    def __init__(self, engine):
        self.engine = engine
        self.verbose = engine.config.get('verbose', False)
        self.differential = DifferentialEngine(engine)
        self._raw_findings = []
        # Concurrency settings from engine config
        self._baseline_workers = engine.config.get(
            'baseline_workers', _DEFAULT_BASELINE_WORKERS,
        )
        self._dispatch_workers_count = engine.config.get(
            'dispatch_workers', _DEFAULT_DISPATCH_WORKERS,
        )
        turbo = engine.config.get('turbo', False)
        if turbo:
            self._baseline_workers = max(self._baseline_workers, 20)
            self._dispatch_workers_count = max(self._dispatch_workers_count, 8)

    def run(self, scan_queue: List) -> List:
        """Process scan queue through all gates and workers.

        Returns raw findings (pre-verification).
        """
        self.engine.emit_pipeline_event('phase8_start', {'queue_size': len(scan_queue)})
        total = len(scan_queue)
        skipped = 0

        # ── GATE 0: Pre-scan triage (filter out static assets) ──
        active_items = []
        for item in scan_queue:
            if self._should_skip(item):
                skipped += 1
            else:
                active_items.append(item)

        # ── GATE 1: Parallel baseline capture ──
        baselines = self._capture_baselines_parallel(active_items)

        # ── GATE 2 + Worker dispatch ──
        for item in active_items:
            key = f"{item.method}:{item.url}:{item.param}"
            baseline = baselines.get(key, {})
            surfaces = SurfaceMapper.map_surfaces(item)
            self._dispatch_workers(item, baseline, surfaces)

            # Rate limit
            if hasattr(self.engine, 'scope'):
                self.engine.scope.enforce_rate_limit()

        processed = len(active_items)
        self.engine.emit_pipeline_event('phase8_complete', {
            'processed': processed,
            'skipped': skipped,
            'raw_findings': len(self._raw_findings),
        })

        if self.verbose:
            msg = (f'Worker pool: processed {processed}/{total}, '
                   f'skipped {skipped}, raw findings: {len(self._raw_findings)}')
            print(Colors.info(msg))

        return self._raw_findings

    def _capture_baselines_parallel(self, items: List) -> Dict[str, Dict]:
        """Capture baselines for all items in parallel using ThreadPoolExecutor.

        Returns a dict mapping ``method:url:param`` → baseline dict.
        """
        baselines: Dict[str, Dict] = {}
        if not items:
            return baselines

        # Deduplicate tasks by key (avoid redundant baseline requests)
        tasks: Dict[str, tuple] = {}
        for item in items:
            key = f"{item.method}:{item.url}:{item.param}"
            if key not in tasks:
                tasks[key] = (item.url, item.method, item.param, item.value)

        worker_count = min(self._baseline_workers, len(tasks))
        if worker_count <= 1:
            # Single-threaded fallback
            for key, (url, method, param, value) in tasks.items():
                baselines[key] = self.differential.set_baseline(url, method, param, value)
            return baselines

        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            future_to_key = {}
            for key, (url, method, param, value) in tasks.items():
                future = executor.submit(
                    self.differential.set_baseline, url, method, param, value,
                )
                future_to_key[future] = key

            for future in as_completed(future_to_key):
                key = future_to_key[future]
                try:
                    baselines[key] = future.result()
                except Exception:
                    baselines[key] = {}

        return baselines

    def _should_skip(self, item) -> bool:
        """Gate 0: Pre-scan triage — skip static assets."""
        if getattr(item, 'endpoint_type', '') == 'STATIC':
            return True
        parsed = urlparse(item.url)
        path = parsed.path.lower()
        return any(path.endswith(ext) for ext in STATIC_EXTENSIONS)

    def _dispatch_workers(self, item, baseline: Dict, surfaces: List):
        """Run applicable worker categories against the scan item.

        Worker categories are dispatched concurrently via ThreadPoolExecutor
        when the dispatch_workers config is > 1 (or --turbo is enabled).
        """
        modules = self.engine._modules

        def _worker_a():
            """Worker A: Injection modules."""
            for mod_key in WORKER_MODULE_MAP['injection']:
                if mod_key in modules:
                    self._run_module(modules[mod_key], item, baseline)

        def _worker_b():
            """Worker B: Auth & Access Control."""
            for mod_key in WORKER_MODULE_MAP['auth']:
                if mod_key in modules:
                    self._run_module(modules[mod_key], item, baseline)

        def _worker_c():
            """Worker C: Business Logic."""
            for mod_key in WORKER_MODULE_MAP['bizlogic']:
                if mod_key in modules:
                    self._run_module(modules[mod_key], item, baseline)

        def _worker_d():
            """Worker D: Misconfiguration."""
            for mod_key in WORKER_MODULE_MAP['misconfig']:
                if mod_key in modules:
                    self._run_url_module(modules[mod_key], item)

        def _worker_cloud():
            """Worker Cloud: Cloud & OSINT modules."""
            for mod_key in WORKER_MODULE_MAP['cloud']:
                if mod_key in modules:
                    self._run_module(modules[mod_key], item, baseline)
                    self._run_url_module(modules[mod_key], item)

        def _worker_e():
            """Worker E: Crypto & Transport (inline checks)."""
            self._check_crypto_transport(item, baseline)

        workers = [_worker_a, _worker_b, _worker_c, _worker_d, _worker_cloud, _worker_e]

        if self._dispatch_workers_count > 1:
            # Concurrent dispatch — run worker categories in parallel
            pool_size = min(self._dispatch_workers_count, len(workers))
            with ThreadPoolExecutor(max_workers=pool_size) as executor:
                futures = [executor.submit(w) for w in workers]
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if self.verbose:
                            print(Colors.warning(f'Worker dispatch error: {e}'))
        else:
            # Sequential fallback (safe mode)
            for w in workers:
                try:
                    w()
                except Exception as e:
                    if self.verbose:
                        print(Colors.warning(f'Worker dispatch error: {e}'))

    def _run_module(self, module, item, baseline: Dict):
        """Run a parameter-testing module against a scan item.

        If the scan item has an explicit ``param``, test that parameter.
        Otherwise, fall back to extracting query-string parameters from
        the URL itself so that endpoints like ``/page.php?id=1`` are
        still tested even when no enriched param entry was created.
        """
        if not hasattr(module, 'test'):
            return

        try:
            if item.param:
                module.test(item.url, item.method, item.param, item.value)
            else:
                # Fallback: extract parameters from the URL query string
                parsed = urlparse(item.url)
                if parsed.query:
                    qs = parse_qs(parsed.query, keep_blank_values=True)
                    for p_name, p_vals in qs.items():
                        p_val = p_vals[0] if p_vals else ''
                        module.test(item.url, item.method, p_name, p_val)
        except Exception as e:
            if self.verbose:
                name = getattr(module, 'name', 'unknown')
                print(Colors.warning(f'Worker error ({name}): {e}'))

    def _run_url_module(self, module, item):
        """Run a URL-level testing module."""
        try:
            if hasattr(module, 'test_url'):
                module.test_url(item.url)
        except Exception as e:
            if self.verbose:
                name = getattr(module, 'name', 'unknown')
                print(Colors.warning(f'Worker URL error ({name}): {e}'))

    def _check_crypto_transport(self, item, baseline: Dict):
        """Worker E: Check TLS, cookies, rate limiting."""
        from core.engine import Finding

        headers = baseline.get('headers', {})

        # Cookie security checks
        set_cookie = headers.get('Set-Cookie', '') or headers.get('set-cookie', '')
        if set_cookie:
            if 'secure' not in set_cookie.lower():
                self.engine.add_finding(Finding(
                    technique='Missing Secure Flag on Cookie',
                    url=item.url,
                    severity='LOW',
                    confidence=0.9,
                    evidence=f'Set-Cookie: {set_cookie[:100]}',
                    remediation='Add Secure flag to all session cookies.',
                ))
            if 'httponly' not in set_cookie.lower():
                self.engine.add_finding(Finding(
                    technique='Missing HttpOnly Flag on Cookie',
                    url=item.url,
                    severity='LOW',
                    confidence=0.9,
                    evidence=f'Set-Cookie: {set_cookie[:100]}',
                    remediation='Add HttpOnly flag to prevent XSS-based cookie theft.',
                ))
            if 'samesite' not in set_cookie.lower():
                self.engine.add_finding(Finding(
                    technique='Missing SameSite Attribute on Cookie',
                    url=item.url,
                    severity='INFO',
                    confidence=0.85,
                    evidence=f'Set-Cookie: {set_cookie[:100]}',
                    remediation='Add SameSite=Lax or SameSite=Strict to cookies.',
                ))

        # Security headers check
        missing_headers = []
        recommended = {
            'Strict-Transport-Security': 'HSTS',
            'Content-Security-Policy': 'CSP',
            'X-Frame-Options': 'Clickjacking protection',
            'X-Content-Type-Options': 'MIME sniffing protection',
            'Permissions-Policy': 'Feature policy',
        }
        headers_lower = {k.lower(): v for k, v in headers.items()}
        for header, desc in recommended.items():
            if header.lower() not in headers_lower:
                missing_headers.append(f"{header} ({desc})")

        if missing_headers:
            self.engine.add_finding(Finding(
                technique='Missing Security Headers',
                url=item.url,
                severity='INFO',
                confidence=0.9,
                evidence=f'Missing: {", ".join(missing_headers[:5])}',
                remediation='Add recommended security headers: ' + ', '.join(h.split(' (')[0] for h in missing_headers[:5]),
            ))

        # Information disclosure via headers
        dangerous_headers = ['x-powered-by', 'server']
        for dh in dangerous_headers:
            val = headers_lower.get(dh, '')
            if val and re.search(r'\d+\.\d+', val):  # Version string detected (major.minor)
                self.engine.add_finding(Finding(
                    technique='Server Version Disclosure',
                    url=item.url,
                    severity='INFO',
                    confidence=0.85,
                    evidence=f'{dh}: {val}',
                    remediation='Remove or sanitize version information from server headers.',
                ))
