#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v8.2 - Recon Runner
Encapsulates the reconnaissance portion of the scan pipeline:
  - Shield detection (CDN/WAF)
  - Real IP discovery
  - Passive recon fan-out
  - Legacy discovery path (crawling, port scan, tech/net exploits)
  - Scope filtering

Returns a ``ReconResult`` that downstream runners consume.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

from config import Colors, Config

if TYPE_CHECKING:
    from core.engine import AtomicEngine


@dataclass
class ReconResult:
    """Aggregated output of the recon phase."""

    urls: Set[str] = field(default_factory=set)
    forms: list = field(default_factory=list)
    parameters: list = field(default_factory=list)
    shield_profile: Optional[Dict[str, Any]] = None
    real_ip_result: Optional[Dict[str, Any]] = None
    fanout_result: Any = None


class ReconRunner:
    """Execute the recon pipeline partition.

    This runner extracts recon logic previously embedded in
    ``AtomicEngine.scan()`` into a focused, testable unit.
    """

    def __init__(self, engine: 'AtomicEngine'):
        self.engine = engine
        self.config = engine.config
        self.modules_config = self.config.get('modules', {})

    # ------------------------------------------------------------------

    def run(self, target: str, init_resp: Any = None) -> ReconResult:
        """Execute the full recon phase and return ``ReconResult``."""
        result = ReconResult()

        # ── PHASE 1: SHIELD DETECTION (CDN + WAF) ────────────────────
        result.shield_profile = self._shield_detect(target, init_resp)

        # ── PHASE 2: REAL IP DISCOVERY ────────────────────────────────
        result.real_ip_result = self._real_ip_discover(target, result.shield_profile)

        # ── PHASE 5: PASSIVE RECON & DISCOVERY (fan-out) ──────────────
        result.fanout_result = self._passive_recon(target)

        if result.fanout_result is not None:
            result.urls = result.fanout_result.urls
            result.forms = result.fanout_result.forms
            result.parameters = result.fanout_result.params
        else:
            # Fallback: legacy discovery path
            urls, forms, parameters = self._legacy_discovery(target)
            result.urls = urls
            result.forms = forms
            result.parameters = parameters

        return result

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _shield_detect(self, target: str, init_resp: Any) -> Optional[Dict]:
        if not self.modules_config.get('shield_detect', False):
            return None
        try:
            from core.shield_detector import ShieldDetector
            shield = ShieldDetector(self.engine)
            probe_result = {'response': init_resp, 'reachable': True, 'latency': 0}
            profile = shield.run(target, probe_result)
            self.engine.emit_pipeline_event('shield_detection', {
                'cdn_detected': profile.get('cdn', {}).get('detected', False),
                'waf_detected': profile.get('waf', {}).get('detected', False),
                'cdn_provider': profile.get('cdn', {}).get('provider'),
                'waf_provider': profile.get('waf', {}).get('provider'),
            })
            return profile
        except Exception as e:
            if self.config.get('verbose'):
                print(f"{Colors.error(f'Shield detection error: {e}')}")
            return None

    def _real_ip_discover(self, target: str, shield_profile: Optional[Dict]) -> Optional[Dict]:
        if not self.modules_config.get('real_ip', False):
            return None
        needs_discovery = True
        if shield_profile:
            needs_discovery = shield_profile.get('needs_origin_discovery', False)
        if not needs_discovery:
            return None
        try:
            from core.real_ip_scanner import RealIPScanner
            scanner = RealIPScanner(self.engine)
            result = scanner.run(target, shield_profile)
            self.engine.emit_pipeline_event('real_ip_discovery', {
                'origin_ip': result.get('origin_ip'),
                'confidence': result.get('confidence'),
                'method': result.get('method'),
                'candidates': len(result.get('all_candidates', [])),
            })
            return result
        except Exception as e:
            if self.config.get('verbose'):
                print(f"{Colors.error(f'Real IP discovery error: {e}')}")
            return None

    def _passive_recon(self, target: str):
        if not self.modules_config.get('passive_recon', False):
            return None
        try:
            from core.passive_recon import PassiveReconFanout
            fanout = PassiveReconFanout(self.engine)
            result = fanout.run(target)
            self.engine.emit_pipeline_event('phase5_result', result.to_dict())
            return result
        except Exception as e:
            if self.config.get('verbose'):
                print(f"{Colors.error(f'Phase 5 fan-out error: {e}')}")
            return None

    def _legacy_discovery(self, target: str) -> Tuple[Set[str], list, list]:
        """Run legacy crawl + discovery when passive recon is disabled."""
        mc = self.modules_config

        # Reconnaissance (optional)
        if mc.get('recon', False):
            try:
                from modules.reconnaissance import ReconModule
                recon = ReconModule(self.engine)
                recon.run(target)
            except Exception as e:
                if self.config.get('verbose'):
                    print(f"{Colors.error(f'Recon error: {e}')}")

        # Port scanning + network exploit scanning
        port_results: list = []
        port_spec = mc.get('ports')
        if port_spec:
            try:
                from modules.port_scanner import PortScanner
                scanner = PortScanner(self.engine)
                hostname = urlparse(target).hostname
                port_results = scanner.run(hostname, port_spec)
            except Exception as e:
                if self.config.get('verbose'):
                    print(f"{Colors.error(f'Port scan error: {e}')}")

        if port_results and mc.get('net_exploit', False):
            try:
                from modules.network_exploits import NetworkExploitScanner
                net_exploit = NetworkExploitScanner(self.engine)
                hostname = urlparse(target).hostname
                net_exploit.run(hostname, port_results)
            except Exception as e:
                if self.config.get('verbose'):
                    print(f"{Colors.error(f'Network exploit scan error: {e}')}")

        # Technology exploit scanning
        if mc.get('tech_exploit', False):
            try:
                from modules.tech_exploits import TechExploitScanner
                tech_exploit = TechExploitScanner(self.engine)
                tech_exploit.run(target)
            except Exception as e:
                if self.config.get('verbose'):
                    print(f"{Colors.error(f'Technology exploit scan error: {e}')}")

        # Crawl target
        from utils.crawler import Crawler
        crawler = Crawler(self.engine)
        depth = min(
            self.config.get('depth', 3) + self.engine.adaptive.get_depth_boost(),
            Config.MAX_DEPTH,
        )
        print(f"{Colors.info(f'Crawling with depth {depth}...')}")
        urls, forms, parameters = crawler.crawl(target, depth)
        print(f"{Colors.info(f'Found {len(urls)} URLs, {len(forms)} forms, {len(parameters)} parameters')}")

        if self.config.get('verbose') and crawler.endpoint_graph:
            print(f"{Colors.info('Endpoint graph:')}")
            print(crawler.get_graph_summary())

        # Scope filter
        urls = self.engine.scope.filter_urls(urls)
        parameters = self.engine.scope.filter_parameters(parameters)

        # Discovery module
        if mc.get('discovery', False):
            try:
                from modules.discovery import DiscoveryModule
                discovery = DiscoveryModule(self.engine)
                discovery.run(target, crawler=crawler)

                for ep in discovery.endpoints:
                    if ep not in urls and self.engine.scope.is_in_scope(ep):
                        urls.add(ep)
                        self.engine.adaptive.add_new_endpoint(ep)
                        ep_parsed = urlparse(ep)
                        if ep_parsed.query:
                            for name, values in parse_qs(ep_parsed.query).items():
                                for val in values:
                                    parameters.append((ep, 'get', name, val, 'discovery'))
            except Exception as e:
                if self.config.get('verbose'):
                    print(f"{Colors.error(f'Discovery error: {e}')}")

        return urls, forms, parameters
