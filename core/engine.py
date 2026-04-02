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

import time
import uuid
import json
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, parse_qs


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
    'open redirect': 'Validate and whitelist redirect URLs. Avoid using user input in redirect targets.',
    'crlf': 'Strip or encode CR/LF characters from user input before including in HTTP headers.',
    'http parameter pollution': 'Normalize duplicate parameters server-side. Validate input at each processing layer.',
    'network exploit': 'Patch or upgrade affected network services. Restrict access via firewall rules and network segmentation.',
    'tech exploit': 'Update detected technologies and frameworks to latest versions. Remove version disclosure headers.',
    'missing security header': 'Add recommended security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options).',
}


@dataclass
class Finding:
    """Vulnerability finding"""
    technique: str = ''
    url: str = ''
    method: str = 'GET'
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
        from core.ai_engine import AIEngine
        from core.persistence import PersistenceEngine

        self.scope = ScopePolicy(self)
        self.context = ContextIntelligence(self)
        self.prioritizer = EndpointPrioritizer(self)
        self.baseline_engine = BaselineEngine(self)
        self.scorer = SignalScorer(self)
        self.verifier = Verifier(self)
        self.learning = LearningStore(self)
        self.adaptive = AdaptiveController(self)
        self.ai = AIEngine(self)
        self.persistence = PersistenceEngine(self)

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
            'open_redirect': ('modules.open_redirect', 'OpenRedirectModule'),
            'crlf': ('modules.crlf', 'CRLFModule'),
            'hpp': ('modules.hpp', 'HPPModule'),
            'graphql': ('modules.graphql', 'GraphQLModule'),
            'proto_pollution': ('modules.proto_pollution', 'ProtoPollutionModule'),
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
        self.start_time = datetime.now(timezone.utc)

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

        # Port scanning (optional) + network exploit scanning
        port_spec = modules_config.get('ports')
        port_results = []
        if port_spec:
            try:
                from modules.port_scanner import PortScanner
                scanner = PortScanner(self)
                hostname = urlparse(target).hostname
                port_results = scanner.run(hostname, port_spec)
            except Exception as e:
                if self.config.get('verbose'):
                    print(f"{Colors.error(f'Port scan error: {e}')}")

        # Network exploit scanning (runs after port scan)
        if port_results and modules_config.get('net_exploit', False):
            try:
                from modules.network_exploits import NetworkExploitScanner
                net_exploit = NetworkExploitScanner(self)
                hostname = urlparse(target).hostname
                net_exploit.run(hostname, port_results)
            except Exception as e:
                if self.config.get('verbose'):
                    print(f"{Colors.error(f'Network exploit scan error: {e}')}")

        # Technology exploit scanning
        if modules_config.get('tech_exploit', False):
            try:
                from modules.tech_exploits import TechExploitScanner
                tech_exploit = TechExploitScanner(self)
                tech_exploit.run(target)
            except Exception as e:
                if self.config.get('verbose'):
                    print(f"{Colors.error(f'Technology exploit scan error: {e}')}")

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

        # ── AI: Predict vulnerabilities and build attack strategy ─────
        ai_strategy = self.ai.get_attack_strategy(target, enriched_params)
        if self.config.get('verbose') and ai_strategy['module_order']:
            module_order = ai_strategy['module_order']
            print(f"{Colors.info(f'AI recommended module order: {module_order}')}")

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

        # ── §7. ADAPTIVE TESTING (AI-driven module selection) ────────
        # Determine module execution order via AI strategy
        ordered_modules = []
        if ai_strategy['module_order']:
            for mkey in ai_strategy['module_order']:
                if mkey in self._modules:
                    ordered_modules.append((mkey, self._modules[mkey]))
            # Append any remaining modules not in AI order
            for mkey, minst in self._modules.items():
                if mkey not in ai_strategy['module_order']:
                    ordered_modules.append((mkey, minst))
        else:
            ordered_modules = list(self._modules.items())

        # ── Reflection Gate ──────────────────────────────────────────
        # Modules that only make sense when user input is reflected in
        # the response body.  If no reflection is detected for a param,
        # these modules are skipped to avoid useless payload spam.
        REFLECTION_DEPENDENT_MODULES = {'xss', 'ssti'}
        reflection_cache = {}  # (url, method, param) → bool

        for ep in enriched_params:
            r_key = (ep['url'], ep['method'], ep['param'])
            if r_key not in reflection_cache:
                reflection_cache[r_key] = self.baseline_engine.reflection_check(
                    ep['url'], ep['method'], ep['param'], ep['value'],
                )

        reflected_count = sum(1 for v in reflection_cache.values() if v)
        skipped_count = len(reflection_cache) - reflected_count
        if skipped_count > 0:
            print(f"{Colors.info(f'Reflection gate: {reflected_count} reflected, {skipped_count} non-reflected (XSS/SSTI skipped)')}")

        for module_key, module_instance in ordered_modules:
            print(f"\n{Colors.info(f'Running {module_instance.name} module...')}")

            for ep in enriched_params:
                ep_key = f"{module_key}:{ep['method']}:{ep['url']}:{ep['param']}"

                # Skip already tested endpoints (persistence / resume)
                if self.persistence.is_tested(ep_key):
                    continue

                # ── Reflection Gate: skip reflection-dependent modules
                # when the parameter value is not reflected in responses.
                if module_key in REFLECTION_DEPENDENT_MODULES:
                    r_key = (ep['url'], ep['method'], ep['param'])
                    if not reflection_cache.get(r_key, False):
                        self.persistence.mark_tested(ep_key)
                        continue

                def _do_test(m=module_instance, e=ep):
                    self.scope.enforce_rate_limit()
                    delay = self.adaptive.get_delay()
                    if delay > 0:
                        time.sleep(delay)
                    if hasattr(m, 'test'):
                        m.test(e['url'], e['method'], e['param'], e['value'])
                    return True

                self.persistence.execute_with_retry(_do_test, ep_key)

            # URL-level checks (CORS, JWT, etc.) — in priority order
            for url_item, _score in prioritized_urls:
                url_key = f"{module_key}:url:{url_item}"
                if self.persistence.is_tested(url_key):
                    continue

                def _do_url_test(m=module_instance, u=url_item):
                    if hasattr(m, 'test_url'):
                        m.test_url(u)
                    return True

                self.persistence.execute_with_retry(_do_url_test, url_key)

        # ── Persistence: save progress ────────────────────────────────
        self.persistence.save_progress()

        # ── §8. MULTI-SIGNAL ANALYSIS (scoring enrichment) ───────────
        self._enrich_finding_signals()

        # ── §9. ADAPTIVE VERIFICATION ────────────────────────────────
        self.findings = self.verifier.verify_findings(self.findings)

        # ── SELF-LEARNING ────────────────────────────────────────────
        for f in self.findings:
            self.learning.record_success(f.technique, f.payload)
            self.ai.record_finding(f.technique, f.param, f.payload)
        self.learning.update_thresholds(self.findings)
        self.learning.save()
        self.ai.save()

        # ── ADAPTIVE LOOP (re-discovery if needed) ───────────────────
        MAX_REDISCOVERY_ROUNDS = 3
        rediscovery_count = 0
        while (self.adaptive.should_rediscover()
               and modules_config.get('discovery', False)
               and rediscovery_count < MAX_REDISCOVERY_ROUNDS):
            rediscovery_count += 1
            try:
                new_params = []
                for ep_url in list(self.adaptive.new_endpoints):
                    if not self.scope.is_in_scope(ep_url):
                        continue
                    ep_parsed = urlparse(ep_url)
                    if ep_parsed.query:
                        for name, values in parse_qs(ep_parsed.query).items():
                            for val in values:
                                new_params.append((ep_url, 'get', name, val, 'adaptive'))
                self.adaptive.new_endpoints.clear()  # reset after processing
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
                break

        # ── Post-exploitation ────────────────────────────────────────
        # AI-driven auto-exploit: orchestrates data extraction, shell
        # upload, and system enumeration based on confirmed findings.
        if modules_config.get('auto_exploit', False) and self.findings:
            try:
                from core.post_exploit import PostExploitEngine
                post_engine = PostExploitEngine(self)
                self.post_exploit_results = post_engine.run(self.findings)
            except Exception as e:
                if self.config.get('verbose'):
                    print(f"{Colors.error(f'Post-exploitation error: {e}')}")

        # Legacy manual flags kept for backward compatibility
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

        if modules_config.get('os_shell', False) and self.findings:
            try:
                from core.os_shell import OSShellHandler
                handler = OSShellHandler(self)
                handler.run(self.findings, forms)
            except Exception as e:
                if self.config.get('verbose'):
                    print(f"{Colors.error(f'OS shell error: {e}')}")

        if modules_config.get('brute', False):
            try:
                from modules.brute_force import BruteForceModule
                bruter = BruteForceModule(self)
                bruter.run(forms)
            except Exception as e:
                if self.config.get('verbose'):
                    print(f"{Colors.error(f'Brute force error: {e}')}")

        if modules_config.get('exploit_chain', False) and self.findings:
            try:
                from core.exploit_chain import ExploitChainEngine
                chainer = ExploitChainEngine(self)
                chainer.run(self.findings)
            except Exception as e:
                if self.config.get('verbose'):
                    print(f"{Colors.error(f'Exploit chain error: {e}')}")

        self.end_time = datetime.now(timezone.utc)

        # ── Clear persistence progress on complete scan ───────────────
        self.persistence.clear_progress()

        # ── Update database record with final metrics ────────────────
        if self.db:
            try:
                self.db.update_scan(
                    self.scan_id,
                    end_time=self.end_time,
                    findings_count=len(self.findings),
                    total_requests=self.requester.total_requests,
                )
            except Exception as e:
                if self.config.get('verbose'):
                    print(f"{Colors.warning(f'Could not update scan record: {e}')}")

        # ── Print summary ────────────────────────────────────────────
        self._print_summary()

    def _enrich_finding_signals(self):
        """Run multi-signal analysis on existing findings to refine confidence."""
        for finding in self.findings:
            baseline = self.baseline_engine.get_baseline(
                finding.url, finding.method, finding.param, '',
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

        # AI Intelligence summary
        ai_summary = self.ai.get_ai_summary()
        if ai_summary['total_patterns'] > 0:
            print(f"\n  {Colors.CYAN}AI Intelligence:{Colors.RESET}")
            print(f"    Learned patterns: {ai_summary['total_patterns']}")
            print(f"    Successful techniques: {ai_summary['successful_techniques']}")

        # Persistence summary
        persist_summary = self.persistence.get_persistence_summary()
        if persist_summary['total_retries'] > 0:
            print(f"\n  {Colors.CYAN}Persistence:{Colors.RESET}")
            print(f"    Endpoints tested: {persist_summary['tested']}")
            print(f"    Total retries: {persist_summary['total_retries']}")
            print(f"    Evasion level: {persist_summary['current_evasion']}")
            if persist_summary['exhausted'] > 0:
                print(f"    Exhausted: {persist_summary['exhausted']}")

        print(f"{Colors.BOLD}{'='*60}{Colors.RESET}")

    def generate_reports(self):
        """Generate reports for the current scan"""
        try:
            from core.reporter import ReportGenerator
            output_dir = self.config.get('output_dir', Config.REPORTS_DIR)
            generator = ReportGenerator(
                self.scan_id, self.findings, self.target,
                self.start_time, self.end_time,
                self.requester.total_requests,
                output_dir=output_dir,
            )
            generator.generate('html')
            generator.generate('json')
        except Exception as e:
            if self.config.get('verbose'):
                print(f"{Colors.error(f'Report generation error: {e}')}")
