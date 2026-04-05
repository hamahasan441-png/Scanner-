#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v9.0 - Verify Runner
Encapsulates the verification & exploit enrichment portion of the pipeline:
  - §9 Adaptive verification (finding dedup, repro, demotion)
  - Self-learning feedback
  - Adaptive re-discovery loop
  - PHASE 9: Post-worker verification (exploit chain detection)
  - PHASE 9B: Exploit reference searcher

Returns a ``VerifyResult`` consumed by downstream runners.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from config import Colors

if TYPE_CHECKING:
    from core.engine import AtomicEngine


@dataclass
class VerifyResult:
    """Aggregated output of the verify phase."""

    verification_result: Any = None
    exploit_chains: list = field(default_factory=list)


class VerifyRunner:
    """Execute the verification pipeline partition.

    Extracts verification logic previously in ``AtomicEngine.scan()``
    into a focused, testable unit.
    """

    def __init__(self, engine: 'AtomicEngine'):
        self.engine = engine
        self.config = engine.config
        self.modules_config = self.config.get('modules', {})

    # ------------------------------------------------------------------

    def run(self, target: str, shield_profile: Optional[Dict] = None) -> VerifyResult:
        """Run all verification stages and return ``VerifyResult``."""
        result = VerifyResult()

        # §9: Adaptive verification
        self.engine.findings = self.engine.verifier.verify_findings(self.engine.findings)

        # Self-learning
        for f in self.engine.findings:
            self.engine.learning.record_success(f.technique, f.payload)
            self.engine.ai.record_finding(f.technique, f.param, f.payload)
        self.engine.learning.update_thresholds(self.engine.findings)
        self.engine.learning.save()
        self.engine.ai.save()

        # Adaptive re-discovery loop
        self._adaptive_rediscovery(target)

        # PHASE 9: Post-worker verification
        result.verification_result = self._post_worker_verify(shield_profile)
        if result.verification_result and hasattr(result.verification_result, 'exploit_chains'):
            result.exploit_chains = result.verification_result.exploit_chains

        # PHASE 9B: Exploit reference searcher
        self._exploit_search()

        return result

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _adaptive_rediscovery(self, target: str):
        MAX_ROUNDS = 3
        count = 0
        mc = self.modules_config
        while (self.engine.adaptive.should_rediscover()
               and mc.get('discovery', False)
               and count < MAX_ROUNDS):
            count += 1
            try:
                new_params: list = []
                for ep_url in list(self.engine.adaptive.new_endpoints):
                    if not self.engine.scope.is_in_scope(ep_url):
                        continue
                    ep_parsed = urlparse(ep_url)
                    if ep_parsed.query:
                        for name, values in parse_qs(ep_parsed.query).items():
                            for val in values:
                                new_params.append((ep_url, 'get', name, val, 'adaptive'))
                self.engine.adaptive.new_endpoints.clear()
                if new_params:
                    enriched = self.engine.context.analyze_parameters(new_params)
                    enriched = self.engine.prioritizer.prioritize_parameters(enriched)
                    for _key, mod in self.engine._modules.items():
                        for ep in enriched:
                            try:
                                if hasattr(mod, 'test'):
                                    mod.test(ep['url'], ep['method'], ep['param'], ep['value'])
                            except Exception:
                                pass
            except Exception as e:
                if self.config.get('verbose'):
                    print(f"{Colors.error(f'Adaptive re-scan error: {e}')}")
                break

    def _post_worker_verify(self, shield_profile):
        if not (self.modules_config.get('chain_detect', False) and self.engine.findings):
            return None
        try:
            from core.post_worker_verifier import PostWorkerVerifier
            pwv = PostWorkerVerifier(self.engine)
            self.engine._shield_profile = shield_profile
            vr = pwv.run(self.engine.findings)
            self.engine.findings = vr.verified_findings

            if vr.exploit_chains:
                self.engine.emit_pipeline_event('exploit_chains_detected', {
                    'chain_count': len(vr.exploit_chains),
                    'chains': [c.to_dict() for c in vr.exploit_chains],
                })
                for chain in vr.exploit_chains:
                    print(f"\n  {Colors.RED}{Colors.BOLD}[CHAIN] {chain.name}{Colors.RESET}")
                    print(f"    CVSS: {chain.combined_cvss}  Severity: {chain.combined_severity}")
                    print(f"    Steps: {' → '.join(chain.steps)}")
            return vr
        except Exception as e:
            if self.config.get('verbose'):
                print(f"{Colors.error(f'Phase 9 verification error: {e}')}")
            return None

    def _exploit_search(self):
        if not (self.modules_config.get('exploit_search', False) and self.engine.findings):
            return
        try:
            from core.exploit_searcher import ExploitSearcher
            searcher = ExploitSearcher(self.engine)
            self.engine.findings = searcher.run(self.engine.findings)
        except Exception as e:
            if self.config.get('verbose'):
                print(f"{Colors.error(f'Phase 9B exploit search error: {e}')}")
