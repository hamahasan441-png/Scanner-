#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v8.2 - Scan Runner
Encapsulates the active scanning portion of the pipeline:
  - Context intelligence & enrichment
  - Attack surface prioritization
  - Baseline building
  - AI-driven adaptive testing (module execution + reflection gate)
  - Scan worker pool
  - Finding signal enrichment

Returns a ``ScanResult`` consumed by the verification and exploit runners.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

from config import Colors, Config

if TYPE_CHECKING:
    from core.engine import AtomicEngine
    from core.runners.recon_runner import ReconResult


@dataclass
class ScanResult:
    """Aggregated output of the scan phase."""

    enriched_params: list = field(default_factory=list)
    prioritized_urls: list = field(default_factory=list)
    intel_bundle: Any = None
    scan_queue: Any = None
    ai_strategy: Optional[Dict] = None


class ScanRunner:
    """Execute the active scanning pipeline partition.

    Extracts scan logic previously in ``AtomicEngine.scan()`` into a
    focused, testable unit.
    """

    def __init__(self, engine: 'AtomicEngine'):
        self.engine = engine
        self.config = engine.config
        self.modules_config = self.config.get('modules', {})

    # ------------------------------------------------------------------

    def run(self, target: str, recon: 'ReconResult', init_resp: Any = None) -> ScanResult:
        """Execute the full scan phase and return ``ScanResult``."""
        result = ScanResult()

        # §3 + §4: Input Extraction & Context Intelligence
        result.enriched_params = self.engine.context.analyze_parameters(recon.parameters)

        # PHASE 6: Intelligence Enrichment
        result.intel_bundle = self._intelligence_enrichment(
            init_resp, recon.parameters, recon.urls)

        # PHASE 7: Attack Surface Prioritization
        result.scan_queue = self._build_scan_queue(
            result.enriched_params, recon.urls, result.intel_bundle,
            recon.real_ip_result, recon.shield_profile, recon.fanout_result)

        # AI strategy
        result.ai_strategy = self.engine.ai.get_attack_strategy(target, result.enriched_params)
        if self.config.get('verbose') and result.ai_strategy.get('module_order'):
            module_order = result.ai_strategy['module_order']
            print(f"{Colors.info(f'AI recommended module order: {module_order}')}")

        # §5: Risk-Based Prioritization
        result.enriched_params = self.engine.prioritizer.prioritize_parameters(result.enriched_params)
        result.prioritized_urls = self.engine.prioritizer.prioritize_urls(recon.urls)

        # §6: Baseline Engine
        self._build_baselines(result.enriched_params)

        # §7: Adaptive Testing (module execution)
        self._run_modules(result.enriched_params, result.prioritized_urls, result.ai_strategy)

        # Persistence save
        self.engine.persistence.save_progress()

        # §8: Multi-signal analysis
        self.engine._enrich_finding_signals()

        # PHASE 8: Scan worker pool
        if result.scan_queue:
            self._run_scan_workers(result.scan_queue)

        return result

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _intelligence_enrichment(self, init_resp, parameters, urls):
        if not self.modules_config.get('enrich', False):
            return None
        try:
            from core.intelligence_enricher import IntelligenceEnricher
            enricher = IntelligenceEnricher(self.engine)
            responses = [init_resp] if init_resp else []
            bundle = enricher.run(responses=responses, params=parameters, urls=urls)
            self.engine.emit_pipeline_event('phase6_result', bundle.to_dict())
            return bundle
        except Exception as e:
            if self.config.get('verbose'):
                print(f"{Colors.error(f'Phase 6 enrichment error: {e}')}")
            return None

    def _build_scan_queue(self, enriched_params, urls, intel_bundle,
                          real_ip_result, shield_profile, fanout_result):
        if not (self.modules_config.get('enrich', False) and intel_bundle):
            return None
        try:
            from core.scan_priority_queue import ScanPriorityQueue
            pq = ScanPriorityQueue(self.engine)
            origin_ip = real_ip_result.get('origin_ip') if real_ip_result else None
            bypass_profile = shield_profile.get('waf', {}) if shield_profile else None
            asset_graph = (fanout_result and hasattr(fanout_result, '_asset_graph')
                           and getattr(fanout_result, '_asset_graph', None))
            queue = pq.build(
                enriched_params=enriched_params, urls=urls,
                intel_bundle=intel_bundle, agent_result=None,
                asset_graph=asset_graph, bypass_profile=bypass_profile,
                origin_ip=origin_ip,
            )
            self.engine.emit_pipeline_event('phase7_result', {'queue_size': len(queue)})
            return queue
        except Exception as e:
            if self.config.get('verbose'):
                print(f"{Colors.error(f'Phase 7 prioritization error: {e}')}")
            return None

    def _build_baselines(self, enriched_params):
        print(f"{Colors.info('Building baselines...')}")
        seen: set = set()
        for ep in enriched_params:
            bkey = f"{ep['method']}:{ep['url']}:{ep['param']}"
            if bkey not in seen:
                seen.add(bkey)
                self.engine.baseline_engine.get_baseline(
                    ep['url'], ep['method'], ep['param'], ep['value'])

    def _run_modules(self, enriched_params, prioritized_urls, ai_strategy):
        """Adaptive module testing with reflection gate."""
        REFLECTION_DEPENDENT = {'xss', 'ssti'}

        # Determine module order
        ordered_modules = []
        if ai_strategy and ai_strategy.get('module_order'):
            for mkey in ai_strategy['module_order']:
                if mkey in self.engine._modules:
                    ordered_modules.append((mkey, self.engine._modules[mkey]))
            for mkey, minst in self.engine._modules.items():
                if mkey not in ai_strategy['module_order']:
                    ordered_modules.append((mkey, minst))
        else:
            ordered_modules = list(self.engine._modules.items())

        # Reflection cache
        reflection_cache: dict = {}
        for ep in enriched_params:
            r_key = (ep['url'], ep['method'], ep['param'])
            if r_key not in reflection_cache:
                reflection_cache[r_key] = self.engine.baseline_engine.reflection_check(
                    ep['url'], ep['method'], ep['param'], ep['value'])

        reflected = sum(1 for v in reflection_cache.values() if v)
        skipped = len(reflection_cache) - reflected
        if skipped > 0:
            print(f"{Colors.info(f'Reflection gate: {reflected} reflected, {skipped} non-reflected (XSS/SSTI skipped)')}")

        for module_key, module_instance in ordered_modules:
            print(f"\n{Colors.info(f'Running {module_instance.name} module...')}")

            for ep in enriched_params:
                ep_key = f"{module_key}:{ep['method']}:{ep['url']}:{ep['param']}"
                if self.engine.persistence.is_tested(ep_key):
                    continue
                if module_key in REFLECTION_DEPENDENT:
                    r_key = (ep['url'], ep['method'], ep['param'])
                    if not reflection_cache.get(r_key, False):
                        self.engine.persistence.mark_tested(ep_key)
                        continue

                def _do_test(m=module_instance, e=ep):
                    self.engine.scope.enforce_rate_limit()
                    delay = self.engine.adaptive.get_delay()
                    if delay > 0:
                        time.sleep(delay)
                    if hasattr(m, 'test'):
                        m.test(e['url'], e['method'], e['param'], e['value'])
                    return True

                self.engine.persistence.execute_with_retry(_do_test, ep_key)

            for url_item, _score in prioritized_urls:
                url_key = f"{module_key}:url:{url_item}"
                if self.engine.persistence.is_tested(url_key):
                    continue

                def _do_url_test(m=module_instance, u=url_item):
                    if hasattr(m, 'test_url'):
                        m.test_url(u)
                    return True

                self.engine.persistence.execute_with_retry(_do_url_test, url_key)

    def _run_scan_workers(self, scan_queue):
        try:
            from core.scan_worker_pool import ScanWorkerPool
            pool = ScanWorkerPool(self.engine)
            pool.run(scan_queue)
            self.engine.emit_pipeline_event('phase8_result', {
                'additional_findings': len(self.engine.findings)})
        except Exception as e:
            if self.config.get('verbose'):
                print(f"{Colors.error(f'Phase 8 worker pool error: {e}')}")
