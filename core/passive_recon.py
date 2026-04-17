#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v9.0 - ULTIMATE EDITION
Phase 5 — Passive Recon & Discovery Fan-Out

Runs recon, port scan, passive URL collection, crawl, and discovery
in a parallel fan-out pattern, then merges all results into a unified
RawURLSet that is scope-filtered and deduplicated.

Usage:
    fan = PassiveReconFanout(engine)
    result = fan.run(target)
    # result.urls, result.forms, result.params, result.recon_bundle, ...
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode

from config import Colors

# ── Data contracts ──────────────────────────────────────────────────────


@dataclass
class ReconBundle:
    """Aggregated reconnaissance data."""

    dns: Dict = field(default_factory=dict)
    whois: Dict = field(default_factory=dict)
    asn: Dict = field(default_factory=dict)
    certs: List[Dict] = field(default_factory=list)
    raw: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "dns": self.dns,
            "whois": self.whois,
            "asn": self.asn,
            "certs": self.certs,
        }


@dataclass
class PortBundle:
    """Port scan results."""

    open_ports: List[int] = field(default_factory=list)
    services: List[Dict] = field(default_factory=list)
    versions: List[Dict] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "open_ports": self.open_ports,
            "services": self.services,
            "versions": self.versions,
        }


@dataclass
class FanoutResult:
    """Merged result of all Phase 5 fan-out operations."""

    urls: Set[str] = field(default_factory=set)
    forms: List = field(default_factory=list)
    params: List[Tuple] = field(default_factory=list)
    recon_bundle: Optional[ReconBundle] = None
    port_bundle: Optional[PortBundle] = None
    passive_urls: List[str] = field(default_factory=list)
    discovery_urls: List[str] = field(default_factory=list)
    crawl_urls: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "total_urls": len(self.urls),
            "total_forms": len(self.forms),
            "total_params": len(self.params),
            "passive_urls": len(self.passive_urls),
            "discovery_urls": len(self.discovery_urls),
            "crawl_urls": len(self.crawl_urls),
            "has_recon": self.recon_bundle is not None,
            "has_ports": self.port_bundle is not None,
        }


# ── URL normalizer / deduplicator ──────────────────────────────────────


class URLDeduplicator:
    """Normalize and deduplicate URLs to canonical form."""

    # Static asset extensions to skip
    STATIC_EXTENSIONS = {
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".svg",
        ".ico",
        ".bmp",
        ".webp",
        ".css",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".otf",
        ".mp3",
        ".mp4",
        ".avi",
        ".mov",
        ".wmv",
        ".flv",
        ".pdf",
        ".zip",
        ".gz",
        ".tar",
        ".rar",
    }

    @classmethod
    def normalize(cls, url: str) -> str:
        """Normalize URL to canonical form for deduplication."""
        parsed = urlparse(url)

        # Lowercase scheme and host
        scheme = parsed.scheme.lower() or "http"
        host = parsed.netloc.lower()
        path = parsed.path.rstrip("/") or "/"

        # Sort query parameters for consistent ordering
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            sorted_params = sorted(params.items())
            query = urlencode(sorted_params, doseq=True)
        else:
            query = ""

        return urlunparse((scheme, host, path, "", query, ""))

    @classmethod
    def is_static(cls, url: str) -> bool:
        """Check if URL points to a static asset."""
        parsed = urlparse(url)
        path = parsed.path.lower()
        return any(path.endswith(ext) for ext in cls.STATIC_EXTENSIONS)

    @classmethod
    def deduplicate(cls, urls) -> Set[str]:
        """Normalize and deduplicate a collection of URLs."""
        seen = set()
        result = set()
        for url in urls:
            norm = cls.normalize(url)
            if norm not in seen:
                seen.add(norm)
                result.add(url)  # keep original form
        return result


# ── Passive URL Collector ──────────────────────────────────────────────


class PassiveURLCollector:
    """Collect URLs from passive sources (Wayback, Common Crawl CDX)."""

    # CDX API endpoints
    WAYBACK_CDX = "https://web.archive.org/cdx/search/cdx"
    COMMON_CRAWL_CDX = "https://index.commoncrawl.org/CC-MAIN-2024-10-index"

    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.verbose = engine.config.get("verbose", False)
        self._max_results = engine.config.get("passive_url_limit", 500)

    def collect(self, domain: str) -> List[str]:
        """Collect URLs from all passive sources."""
        urls = []
        urls.extend(self._wayback_urls(domain))
        urls.extend(self._commoncrawl_urls(domain))
        return urls

    def _wayback_urls(self, domain: str) -> List[str]:
        """Fetch URLs from Wayback Machine CDX API."""
        collected = []
        try:
            params = {
                "url": f"*.{domain}/*",
                "output": "text",
                "fl": "original",
                "collapse": "urlkey",
                "limit": str(self._max_results),
                "filter": "statuscode:200",
            }
            resp = self.requester.request(
                self.WAYBACK_CDX,
                "GET",
                params=params,
                timeout=15,
            )
            if resp and resp.status_code == 200:
                for line in resp.text.strip().split("\n"):
                    line = line.strip()
                    if line and line.startswith("http"):
                        collected.append(line)
                if self.verbose:
                    print(f"{Colors.info(f'Wayback CDX: {len(collected)} URLs')}")
        except Exception as e:
            if self.verbose:
                print(f"{Colors.warning(f'Wayback CDX error: {e}')}")
        return collected

    def _commoncrawl_urls(self, domain: str) -> List[str]:
        """Fetch URLs from Common Crawl CDX API."""
        collected = []
        try:
            params = {
                "url": f"*.{domain}",
                "output": "text",
                "fl": "url",
                "limit": str(min(self._max_results, 200)),
            }
            resp = self.requester.request(
                self.COMMON_CRAWL_CDX,
                "GET",
                params=params,
                timeout=15,
            )
            if resp and resp.status_code == 200:
                for line in resp.text.strip().split("\n"):
                    line = line.strip()
                    if line and line.startswith("http"):
                        collected.append(line)
                if self.verbose:
                    print(f"{Colors.info(f'Common Crawl CDX: {len(collected)} URLs')}")
        except Exception as e:
            if self.verbose:
                print(f"{Colors.warning(f'Common Crawl CDX error: {e}')}")
        return collected


# ── Asset Graph ────────────────────────────────────────────────────────


class AssetGraph:
    """Simple directed graph of URL nodes and link edges."""

    def __init__(self):
        self.nodes: Set[str] = set()  # URLs
        self.edges: List[Tuple[str, str]] = []  # (source, target)
        self.metadata: Dict[str, Dict] = {}  # per-node metadata

    def add_node(self, url: str, **meta):
        self.nodes.add(url)
        if meta:
            self.metadata.setdefault(url, {}).update(meta)

    def add_edge(self, source: str, target: str):
        self.edges.append((source, target))
        self.nodes.add(source)
        self.nodes.add(target)

    def get_depth(self, url: str) -> int:
        """Return metadata depth, default 0."""
        return self.metadata.get(url, {}).get("depth", 0)

    def to_dict(self) -> Dict:
        return {
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
        }


# ── Main Fan-Out Orchestrator ──────────────────────────────────────────


class PassiveReconFanout:
    """Phase 5 — Parallel fan-out for recon and discovery.

    Runs recon, port scan, passive URL collection, crawler, and discovery
    in sequence (parallel fan-out simulated via sequential calls with
    engine rate limiting), then merges all results.
    """

    def __init__(self, engine):
        self.engine = engine
        self.config = engine.config
        self.verbose = engine.config.get("verbose", False)
        self.deduplicator = URLDeduplicator()
        self.asset_graph = AssetGraph()

    def run(self, target: str) -> FanoutResult:
        """Execute all Phase 5 fan-out operations and return merged result."""
        result = FanoutResult()
        modules_config = self.config.get("modules", {})
        hostname = urlparse(target).hostname or ""

        self.engine.emit_pipeline_event("phase5_start", {"target": target})

        # ── RECON (if --recon) ──
        if modules_config.get("recon", False):
            result.recon_bundle = self._run_recon(target)

        # ── PORT SCAN (if --ports) ──
        port_spec = modules_config.get("ports")
        if port_spec:
            result.port_bundle = self._run_port_scan(hostname, port_spec)

        # ── PASSIVE URL COLLECTION ──
        if modules_config.get("passive_recon", False):
            result.passive_urls = self._run_passive_urls(hostname)

        # ── CRAWLER ──
        crawl_urls, forms, params = self._run_crawler(target)
        result.crawl_urls = list(crawl_urls)
        result.forms = forms
        result.params = params

        # ── DISCOVERY MODULE (if --discovery) ──
        if modules_config.get("discovery", False):
            result.discovery_urls = self._run_discovery(target)

        # ── MERGE ALL ──
        result = self._merge_results(target, result)

        self.engine.emit_pipeline_event("phase5_complete", result.to_dict())
        return result

    def _run_recon(self, target: str) -> Optional[ReconBundle]:
        """Execute reconnaissance module."""
        bundle = ReconBundle()
        try:
            from modules.reconnaissance import ReconModule

            recon = ReconModule(self.engine)
            recon.run(target)
            bundle.raw = {"completed": True}
            if self.verbose:
                print(f"{Colors.info('Recon bundle collected')}")
        except Exception as e:
            if self.verbose:
                print(f"{Colors.error(f'Recon error: {e}')}")
        return bundle

    def _run_port_scan(self, hostname: str, port_spec) -> Optional[PortBundle]:
        """Execute port scanner."""
        bundle = PortBundle()
        try:
            from modules.port_scanner import PortScanner

            scanner = PortScanner(self.engine)
            port_results = scanner.run(hostname, port_spec)
            for pr in port_results:
                if isinstance(pr, dict):
                    bundle.open_ports.append(pr.get("port", 0))
                    if pr.get("service"):
                        bundle.services.append(pr)
                    if pr.get("version"):
                        bundle.versions.append(pr)

            # Network exploit scanning on open ports
            modules_config = self.config.get("modules", {})
            if port_results and modules_config.get("net_exploit", False):
                try:
                    from modules.network_exploits import NetworkExploitScanner

                    net_exploit = NetworkExploitScanner(self.engine)
                    net_exploit.run(hostname, port_results)
                except Exception as e:
                    if self.verbose:
                        print(f"{Colors.error(f'Network exploit scan error: {e}')}")

            # Technology exploit scanning
            if modules_config.get("tech_exploit", False):
                try:
                    from modules.tech_exploits import TechExploitScanner

                    tech_exploit = TechExploitScanner(self.engine)
                    tech_exploit.run(f"http://{hostname}")
                except Exception as e:
                    if self.verbose:
                        print(f"{Colors.error(f'Tech exploit scan error: {e}')}")

        except Exception as e:
            if self.verbose:
                print(f"{Colors.error(f'Port scan error: {e}')}")
        return bundle

    def _run_passive_urls(self, domain: str) -> List[str]:
        """Collect passive URLs from CDX APIs."""
        collector = PassiveURLCollector(self.engine)
        urls = collector.collect(domain)
        if self.verbose:
            print(f"{Colors.info(f'Passive URL collection: {len(urls)} URLs')}")
        return urls

    def _run_crawler(self, target: str) -> Tuple:
        """Execute crawler with adaptive depth."""
        from utils.crawler import Crawler
        from config import Config

        crawler = Crawler(self.engine)
        depth = min(
            self.config.get("depth", 3) + self.engine.adaptive.get_depth_boost(),
            Config.MAX_DEPTH,
        )
        print(f"{Colors.info(f'Crawling with depth {depth}...')}")
        urls, forms, parameters = crawler.crawl(target, depth)
        print(f"{Colors.info(f'Found {len(urls)} URLs, {len(forms)} forms, {len(parameters)} parameters')}")

        # Build asset graph from crawler results
        if hasattr(crawler, "endpoint_graph") and crawler.endpoint_graph:
            for edge in crawler.endpoint_graph:
                if isinstance(edge, (list, tuple)) and len(edge) >= 2:
                    self.asset_graph.add_edge(edge[0], edge[1])

        for url in urls:
            self.asset_graph.add_node(url)

        return urls, forms, parameters

    def _run_discovery(self, target: str) -> List[str]:
        """Execute discovery module."""
        discovered = []
        try:
            from modules.discovery import DiscoveryModule

            discovery = DiscoveryModule(self.engine)
            discovery.run(target)
            for ep in discovery.endpoints:
                if self.engine.scope.is_in_scope(ep):
                    discovered.append(ep)
            if self.verbose:
                print(f"{Colors.info(f'Discovery: {len(discovered)} new endpoints')}")
        except Exception as e:
            if self.verbose:
                print(f"{Colors.error(f'Discovery error: {e}')}")
        return discovered

    def _merge_results(self, target: str, result: FanoutResult) -> FanoutResult:
        """Merge all URL sources, scope-filter, and deduplicate."""
        # Combine all URL sources into one set
        raw_urls = set(result.crawl_urls)
        for url in result.passive_urls:
            raw_urls.add(url)
        for url in result.discovery_urls:
            raw_urls.add(url)

        # Scope filter
        raw_urls = self.engine.scope.filter_urls(raw_urls)

        # Deduplicate
        result.urls = self.deduplicator.deduplicate(raw_urls)

        # Filter parameters to in-scope only
        result.params = self.engine.scope.filter_parameters(result.params)

        # Add passive URL parameters to params list
        for url in result.passive_urls:
            parsed = urlparse(url)
            if parsed.query and self.engine.scope.is_in_scope(url):
                for name, values in parse_qs(parsed.query).items():
                    for val in values:
                        result.params.append((url, "get", name, val, "passive"))

        # Add discovery URL parameters
        for url in result.discovery_urls:
            parsed = urlparse(url)
            if parsed.query and self.engine.scope.is_in_scope(url):
                for name, values in parse_qs(parsed.query).items():
                    for val in values:
                        result.params.append((url, "get", name, val, "discovery"))

        # Build asset graph
        for url in result.urls:
            self.asset_graph.add_node(url)

        print(f"{Colors.info(f'Merged: {len(result.urls)} unique URLs, {len(result.params)} parameters')}")
        return result
