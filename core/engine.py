#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v8.0 - ULTIMATE EDITION
Core Engine - Scan orchestration and module management

CORE FLOW:
  §1 Scope & Policy → §2 Discover & Graph → §3 Extract & Classify →
  §4 Context Intelligence → §5 Risk-Based Prioritize →
  §6 Baseline → §7 Adaptive Test → §8 Multi-Signal Analyze →
  §9 Adaptive Verify → Report → Learn → Adapt
"""

import os
import sys
import uuid
import json
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config, Colors, MITRE_CWE_MAP

# Remediation suggestions keyed by vulnerability family
REMEDIATION_MAP = {
    'sql injection': 'Use parameterized queries / prepared statements. Apply input validation and least-privilege DB accounts.',
    'xss': 'Encode output contextually (HTML, JS, URL). Use Content-Security-Policy headers.',
    'lfi': 'Validate and whitelist file paths. Disable allow_url_include in PHP.',
    'rfi': 'Disable remote file inclusion (allow_url_include=Off). Whitelist allowed paths.',
    'command injection': 'Avoid passing user input to OS commands. Use safe API alternatives and input validation.',
    'ssrf': 'Validate and whitelist URLs. Block internal/metadata IP ranges at the network level.',
    'ssti': 'Use a sandboxed template engine. Never pass user input directly into templates.',
    'xxe': 'Disable external entity processing in XML parsers. Use JSON where possible.',
    'idor': 'Implement proper authorization checks per object. Use indirect references.',
    'cors': 'Restrict Access-Control-Allow-Origin to trusted domains. Avoid wildcard with credentials.',
    'jwt': 'Enforce strong signing algorithms (RS256+). Validate all claims including expiration.',
    'nosql': 'Sanitize input before MongoDB queries. Avoid $where and operator injection.',
    'file upload': 'Validate file type, size, and content. Store uploads outside webroot.',
}


@dataclass
class Finding:
    """Vulnerability finding"""
    technique: str = ''
    url: str = ''
    param: str = ''
    payload: str = ''
    evidence: str = ''
    severity: str = 'INFO'
    confidence: float = 0.0
    mitre_id: str = ''
    cwe_id: str = ''
    cvss: float = 0.0
    extracted_data: str = ''
    signals: dict = field(default_factory=dict)
    priority: float = 0.0
    remediation: str = ''

    def __post_init__(self):
        # Auto-populate MITRE/CWE from technique name
        for vuln_type, (mitre, cwe) in MITRE_CWE_MAP.items():
            if vuln_type.lower() in self.technique.lower():
                if not self.mitre_id:
                    self.mitre_id = mitre
                if not self.cwe_id:
                    self.cwe_id = cwe
                break
        # Auto-populate remediation suggestion
        if not self.remediation:
            technique_lower = self.technique.lower()
            for key, suggestion in REMEDIATION_MAP.items():
                if key in technique_lower:
                    self.remediation = suggestion
                    break


class AtomicEngine:
    """Core scanning engine"""

    def __init__(self, config: dict):
        self.config = config
        self.scan_id = str(uuid.uuid4())[:8]
        self.findings = []
        self.start_time = None
        self.end_time = None
        self.target = None

        # Initialize evasion engine
        try:
            from utils.evasion import EvasionEngine
            self.evasion = EvasionEngine(config.get('evasion', 'none'))
        except Exception:
            self.evasion = None

        # Initialize requester
        from utils.requester import Requester
        self.requester = Requester(config)

        # Initialize database
        try:
            from utils.database import Database
            self.db = Database()
        except Exception:
            self.db = None

        # --- New intelligence components ---
        from core.scope import ScopePolicy
        from core.context import ContextIntelligence
        from core.prioritizer import EndpointPrioritizer
        from core.baseline import BaselineEngine
        from core.scorer import SignalScorer
        from core.verifier import Verifier
        from core.learning import LearningStore
        from core.adaptive import AdaptiveController

        self.scope = ScopePolicy(self)
        self.context = ContextIntelligence(self)
        self.prioritizer = EndpointPrioritizer(self)
        self.baseline_engine = BaselineEngine(self)
        self.scorer = SignalScorer(self)
        self.verifier = Verifier(self)
        self.learning = LearningStore(self)
        self.adaptive = AdaptiveController(self)

        # Initialize modules
        self._modules = {}
        self._load_modules()

    def _load_modules(self):
        """Load enabled scanning modules"""
        module_map = {
            'sqli': ('modules.sqli', 'SQLiModule'),
            'xss': ('modules.xss', 'XSSModule'),
            'lfi': ('modules.lfi', 'LFIModule'),
            'cmdi': ('modules.cmdi', 'CommandInjectionModule'),
            'ssrf': ('modules.ssrf', 'SSRFModule'),
            'ssti': ('modules.ssti', 'SSTIModule'),
            'xxe': ('modules.xxe', 'XXEModule'),
            'idor': ('modules.idor', 'IDORModule'),
            'nosql': ('modules.nosqli', 'NoSQLModule'),
            'cors': ('modules.cors', 'CORSModule'),
            'jwt': ('modules.jwt', 'JWTModule'),
            'upload': ('modules.uploader', 'ShellUploader'),
        }

        modules_config = self.config.get('modules', {})
        for key, (module_path, class_name) in module_map.items():
            if modules_config.get(key, False):
                try:
                    mod = __import__(module_path, fromlist=[class_name])
                    cls = getattr(mod, class_name)
                    self._modules[key] = cls(self)
                except Exception as e:
                    print(f"{Colors.warning(f'Module {key} failed to load: {e}')}")

    def scan(self, target: str):
        """Scan a target URL.

        Follows the CORE FLOW:
        §1 Scope → §2 Discover → §3 Extract/Classify → §4 Context →
        §5 Prioritize → §6 Baseline → §7 Test → §8 Analyze →
        §9 Verify → Report → Learn → Adapt
        """
        self.target = target
        self.start_time = datetime.utcnow()

        print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
        print(f"{Colors.CYAN}  Scanning: {target}{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*60}{Colors.RESET}\n")

        # ── §1. SCOPE & POLICY ENGINE ────────────────────────────────
        self.scope.set_target_scope(target)
        self.scope.load_robots_txt(target)

        # Test connection
        if not self.requester.test_connection(target):
            print(f"{Colors.error(f'Cannot connect to {target}')}")
            return

        # Tech fingerprinting on initial response
        try:
            init_resp = self.requester.request(target, 'GET')
            if init_resp:
                self.context.fingerprint_response(init_resp)
        except Exception:
            pass

        # Save scan to database
        if self.db:
            self.db.save_scan(
                scan_id=self.scan_id,
                target=target,
                start_time=self.start_time,
                config=json.dumps(self.config, default=str),
            )

        modules_config = self.config.get('modules', {})

        # ── §2. DISCOVERY & GRAPH ENGINE ─────────────────────────────
        # Reconnaissance (optional)
        if modules_config.get('recon', False):
            try:
                from modules.reconnaissance import ReconModule
                recon = ReconModule(self)
                recon.run(target)
            except Exception as e:
                if self.config.get('verbose'):
                    print(f"{Colors.error(f'Recon error: {e}')}")

        # Crawl target
        from utils.crawler import Crawler
        crawler = Crawler(self)
        depth = min(
            self.config.get('depth', 3) + self.adaptive.get_depth_boost(),
            Config.MAX_DEPTH,
        )

        print(f"{Colors.info(f'Crawling with depth {depth}...')}")
        urls, forms, parameters = crawler.crawl(target, depth)
        print(f"{Colors.info(f'Found {len(urls)} URLs, {len(forms)} forms, {len(parameters)} parameters')}")

        # Print graph summary if verbose
        if self.config.get('verbose') and crawler.endpoint_graph:
            print(f"{Colors.info('Endpoint graph:')}")
            print(crawler.get_graph_summary())

        # Scope filter: remove out-of-scope URLs
        urls = self.scope.filter_urls(urls)
        parameters = self.scope.filter_parameters(parameters)

        # Target discovery & enumeration
        if modules_config.get('discovery', False):
            try:
                from modules.discovery import DiscoveryModule
                discovery = DiscoveryModule(self)
                discovery.run(target, crawler=crawler)

                for ep in discovery.endpoints:
                    if ep not in urls and self.scope.is_in_scope(ep):
                        urls.add(ep)
                        self.adaptive.add_new_endpoint(ep)
                        ep_parsed = urlparse(ep)
                        if ep_parsed.query:
                            for name, values in parse_qs(ep_parsed.query).items():
                                for val in values:
                                    parameters.append((ep, 'get', name, val, 'discovery'))
            except Exception as e:
                if self.config.get('verbose'):
                    print(f"{Colors.error(f'Discovery error: {e}')}")

        # ── §3. INPUT EXTRACTION & CLASSIFICATION ────────────────────
        # ── §4. CONTEXT INTELLIGENCE ─────────────────────────────────
        enriched_params = self.context.analyze_parameters(parameters)

        # ── §5. RISK-BASED PRIORITIZATION ────────────────────────────
        enriched_params = self.prioritizer.prioritize_parameters(enriched_params)
        prioritized_urls = self.prioritizer.prioritize_urls(urls)

        # ── §6. BASELINE ENGINE ──────────────────────────────────────
        print(f"{Colors.info('Building baselines...')}")
        seen_baselines = set()
        for ep in enriched_params:
            bkey = f"{ep['method']}:{ep['url']}:{ep['param']}"
            if bkey not in seen_baselines:
                seen_baselines.add(bkey)
                self.baseline_engine.get_baseline(
                    ep['url'], ep['method'], ep['param'], ep['value'],
                )

        # ── §7. ADAPTIVE TESTING (context-driven module selection) ───
        for module_key, module_instance in self._modules.items():
            print(f"\n{Colors.info(f'Running {module_instance.name} module...')}")

            for ep in enriched_params:
                try:
                    # Rate limit enforcement
                    self.scope.enforce_rate_limit()

                    # Adaptive delay
                    import time
                    delay = self.adaptive.get_delay()
                    if delay > 0:
                        time.sleep(delay)

                    if hasattr(module_instance, 'test'):
                        module_instance.test(
                            ep['url'], ep['method'], ep['param'], ep['value'],
                        )
                except Exception as e:
                    if self.config.get('verbose'):
                        print(f"{Colors.error(f'Module error ({module_key}): {e}')}")

            # URL-level checks (CORS, JWT, etc.) — in priority order
            for url, _score in prioritized_urls:
                try:
                    if hasattr(module_instance, 'test_url'):
                        module_instance.test_url(url)
                except Exception as e:
                    if self.config.get('verbose'):
                        print(f"{Colors.error(f'URL test error ({module_key}): {e}')}")

        # ── §8. MULTI-SIGNAL ANALYSIS (scoring enrichment) ───────────
        self._enrich_finding_signals()

        # ── §9. ADAPTIVE VERIFICATION ────────────────────────────────
        self.findings = self.verifier.verify_findings(self.findings)

        # ── SELF-LEARNING ────────────────────────────────────────────
        for f in self.findings:
            self.learning.record_success(f.technique, f.payload)
        self.learning.update_thresholds(self.findings)
        self.learning.save()

        # ── ADAPTIVE LOOP (re-discovery if needed) ───────────────────
        if self.adaptive.should_rediscover() and modules_config.get('discovery', False):
            try:
                new_params = []
                for ep_url in self.adaptive.new_endpoints:
                    if not self.scope.is_in_scope(ep_url):
                        continue
                    ep_parsed = urlparse(ep_url)
                    if ep_parsed.query:
                        for name, values in parse_qs(ep_parsed.query).items():
                            for val in values:
                                new_params.append((ep_url, 'get', name, val, 'adaptive'))
                if new_params:
                    new_enriched = self.context.analyze_parameters(new_params)
                    new_enriched = self.prioritizer.prioritize_parameters(new_enriched)
                    for module_key, module_instance in self._modules.items():
                        for ep in new_enriched:
                            try:
                                if hasattr(module_instance, 'test'):
                                    module_instance.test(
                                        ep['url'], ep['method'], ep['param'], ep['value'],
                                    )
                            except Exception:
                                pass
            except Exception as e:
                if self.config.get('verbose'):
                    print(f"{Colors.error(f'Adaptive re-scan error: {e}')}")

        # ── Post-exploitation ────────────────────────────────────────
        if modules_config.get('shell', False) and self.findings:
            try:
                from modules.uploader import ShellUploader
                uploader = ShellUploader(self)
                uploader.run(self.findings, forms)
            except Exception as e:
                if self.config.get('verbose'):
                    print(f"{Colors.error(f'Shell upload error: {e}')}")

        if modules_config.get('dump', False) and self.findings:
            try:
                from modules.dumper import DataDumper
                dumper = DataDumper(self)
                dumper.run(self.findings)
            except Exception as e:
                if self.config.get('verbose'):
                    print(f"{Colors.error(f'Data dump error: {e}')}")

        self.end_time = datetime.utcnow()

        # ── Print summary ────────────────────────────────────────────
        self._print_summary()

    def _enrich_finding_signals(self):
        """Run multi-signal analysis on existing findings to refine confidence."""
        for finding in self.findings:
            method = getattr(finding, 'method', 'POST')
            baseline = self.baseline_engine.get_baseline(
                finding.url, method, finding.param, '',
            )
            signals = self.scorer.analyze(
                baseline=baseline,
                elapsed=0,
                response_text=finding.evidence,
                payload=finding.payload,
                error_patterns=['error', 'syntax', 'exception', 'warning'],
                baseline_text='',
            )
            finding.signals = signals.to_dict()
            # Boost confidence if multi-signal analysis agrees
            if signals.combined_score > finding.confidence:
                finding.confidence = signals.combined_score

    def add_finding(self, finding: Finding):
        """Add a vulnerability finding"""
        # Validate finding has minimum required fields
        if not finding.technique or not finding.url:
            if self.config.get('verbose'):
                print(f"{Colors.warning('Skipping invalid finding: missing technique or url')}")
            return
        
        # Skip duplicate findings (same technique + url + param)
        for existing in self.findings:
            if (existing.technique == finding.technique and
                existing.url == finding.url and
                existing.param == finding.param):
                return
        
        self.findings.append(finding)

        # Print finding
        severity_color = {
            'CRITICAL': Colors.RED + Colors.BOLD,
            'HIGH': Colors.RED,
            'MEDIUM': Colors.YELLOW,
            'LOW': Colors.CYAN,
            'INFO': Colors.BLUE,
        }.get(finding.severity, Colors.WHITE)

        print(f"\n  {severity_color}[{finding.severity}]{Colors.RESET} {finding.technique}")
        print(f"    URL:     {finding.url}")
        if finding.param:
            print(f"    Param:   {finding.param}")
        if finding.payload:
            payload_display = finding.payload[:80] + '...' if len(finding.payload) > 80 else finding.payload
            print(f"    Payload: {payload_display}")
        if finding.evidence:
            print(f"    Evidence: {finding.evidence[:100]}")

        # Save to database
        if self.db:
            self.db.save_finding(self.scan_id, finding)

    def _print_summary(self):
        """Print scan summary with intelligence insights"""
        duration = (self.end_time - self.start_time).total_seconds() if self.end_time and self.start_time else 0

        print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
        print(f"{Colors.CYAN}  Scan Summary{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*60}{Colors.RESET}")
        print(f"  Scan ID:    {self.scan_id}")
        print(f"  Target:     {self.target}")
        print(f"  Duration:   {duration:.1f}s")
        print(f"  Requests:   {self.requester.total_requests}")
        print(f"  Findings:   {len(self.findings)}")

        # Severity breakdown
        severities = {}
        for f in self.findings:
            severities[f.severity] = severities.get(f.severity, 0) + 1

        if severities:
            print(f"\n  {Colors.BOLD}Severity Breakdown:{Colors.RESET}")
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                if sev in severities:
                    print(f"    {sev}: {severities[sev]}")

        # Scope summary
        scope_summary = self.scope.get_scope_summary()
        if scope_summary['blocked_count'] > 0:
            print(f"\n  {Colors.YELLOW}Scope:{Colors.RESET} {scope_summary['blocked_count']} out-of-scope URLs blocked")

        # Tech fingerprint summary
        if self.context.detected_tech:
            print(f"  {Colors.CYAN}Detected tech:{Colors.RESET} {', '.join(sorted(self.context.detected_tech))}")

        # Adaptive intelligence summary
        adaptive_summary = self.adaptive.get_scan_summary()
        if adaptive_summary.get('waf_detected'):
            print(f"\n  {Colors.YELLOW}WAF Detected:{Colors.RESET} {adaptive_summary['waf_name']}")
        if adaptive_summary.get('block_rate', 0) > 0.1:
            print(f"  Block Rate: {adaptive_summary['block_rate']:.1%}")

        print(f"{Colors.BOLD}{'='*60}{Colors.RESET}")

    def generate_reports(self):
        """Generate reports for the current scan"""
        try:
            from core.reporter import ReportGenerator
            generator = ReportGenerator(self.scan_id, self.findings, self.target, self.start_time, self.end_time, self.requester.total_requests)
            generator.generate('html')
            generator.generate('json')
        except Exception as e:
            if self.config.get('verbose'):
                print(f"{Colors.error(f'Report generation error: {e}')}")
