#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v10.0 - ULTIMATE EDITION
Core Engine - Scan orchestration and module management

CORE FLOW (regulated — canonical phase sequence per ARCHITECTURE_v8_CORRECTED):
  Phase 1:  Init & Normalize
  Phase 2:  Scope & Policy
  Phase 3:  Scan Plan Display (--show-plan)
  Phase 4:  Shield Detection (CDN + WAF)
  Phase 5:  Real IP Discovery
            Build effective target (origin IP when available)
  Phase 6:  Passive Recon & Discovery (fan-out via origin IP)
            OR Legacy: Crawl + Fuzzer Discovery (via origin IP)
  Phase 7:  Intelligence Enrichment
  Phase 8:  Attack Surface Prioritization
  Phase 9:  Vulnerability Scan Workers
  Phase 10: Post-Worker Verification
  Phase 11: Attack Map (exploit-aware attack graph — before report)
  Phase 12: Agent Scan (autonomous goal-driven)
  Phase 13: Commit & Report (OutputPhase)
  Phase 14: Learn → Adapt
"""

import time
import uuid
import json
import logging
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, parse_qs


from config import Config, Colors, MITRE_CWE_MAP
from core.rules_engine import RulesEngine

logger = logging.getLogger(__name__)

# Remediation suggestions keyed by vulnerability family
REMEDIATION_MAP = {
    "sql injection": "Use parameterized queries / prepared statements. Apply input validation and least-privilege DB accounts.",
    "xss": "Encode output contextually (HTML, JS, URL). Use Content-Security-Policy headers.",
    "lfi": "Validate and whitelist file paths. Disable allow_url_include in PHP.",
    "rfi": "Disable remote file inclusion (allow_url_include=Off). Whitelist allowed paths.",
    "command injection": "Avoid passing user input to OS commands. Use safe API alternatives and input validation.",
    "ssrf": "Validate and whitelist URLs. Block internal/metadata IP ranges at the network level.",
    "cloud": "Restrict cloud storage bucket permissions. Disable IMDS or enforce IMDSv2. Rotate exposed credentials immediately.",
    "ssti": "Use a sandboxed template engine. Never pass user input directly into templates.",
    "xxe": "Disable external entity processing in XML parsers. Use JSON where possible.",
    "idor": "Implement proper authorization checks per object. Use indirect references.",
    "cors": "Restrict Access-Control-Allow-Origin to trusted domains. Avoid wildcard with credentials.",
    "jwt": "Enforce strong signing algorithms (RS256+). Validate all claims including expiration.",
    "nosql": "Sanitize input before MongoDB queries. Avoid $where and operator injection.",
    "file upload": "Validate file type, size, and content. Store uploads outside webroot.",
    "open redirect": "Validate and whitelist redirect URLs. Avoid using user input in redirect targets.",
    "crlf": "Strip or encode CR/LF characters from user input before including in HTTP headers.",
    "http parameter pollution": "Normalize duplicate parameters server-side. Validate input at each processing layer.",
    "network exploit": "Patch or upgrade affected network services. Restrict access via firewall rules and network segmentation.",
    "tech exploit": "Update detected technologies and frameworks to latest versions. Remove version disclosure headers.",
    "missing security header": "Add recommended security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options).",
}


@dataclass
class Finding:
    """Vulnerability finding"""

    technique: str = ""
    url: str = ""
    method: str = "GET"
    param: str = ""
    payload: str = ""
    evidence: str = ""
    severity: str = "INFO"
    confidence: float = 0.0
    mitre_id: str = ""
    cwe_id: str = ""
    cvss: float = 0.0
    extracted_data: str = ""
    signals: dict = field(default_factory=dict)
    priority: float = 0.0
    remediation: str = ""
    # Phase 9B exploit enrichment attributes (populated by ExploitSearcher)
    adjusted_cvss: float = 0.0
    adjusted_severity: str = ""
    exploit_availability: str = "THEORETICAL"
    actively_exploited: bool = False
    metasploit_ready: bool = False
    nuclei_ready: bool = False
    exploit_record: object = None
    _exploit_finding_id: str = ""
    github_advisory_id: Optional[str] = None

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
        # Initialize exploit enrichment defaults from base values
        # (only when not already set by Phase 9B enrichment)
        if self.adjusted_cvss == 0.0 and self.cvss != 0.0:
            self.adjusted_cvss = self.cvss
        if not self.adjusted_severity:
            self.adjusted_severity = self.severity


class AtomicEngine:
    """Core scanning engine"""

    def __init__(self, config: dict):
        self.config = config
        self.scan_id = str(uuid.uuid4())[:8]
        self.findings = []
        self.start_time = None
        self.end_time = None
        self.target = None
        self.post_exploit_results = []

        # --- Scanner rules engine ---
        rules_path = config.get("rules_path")
        self.rules = RulesEngine(rules_path=rules_path, config=config)

        # Apply runtime defaults from rules when not set in config
        rt = self.rules.runtime
        if "threads" not in config:
            config["threads"] = rt.get("threads", 10)
        if "timeout" not in config:
            config["timeout"] = rt.get("timeout_seconds", 15)
        if "delay" not in config:
            config["delay"] = rt.get("delay_seconds", 0.25)

        # --- Pipeline tracking (granular phase tracking) ---
        # Uses the canonical phase definitions from pipeline_contract for
        # accurate dashboard position reporting across all 21 phases.
        try:
            from core.pipeline_contract import Phase, Partition, PHASE_PARTITION
            self._phase_enum = Phase
            self._phase_partition = PHASE_PARTITION
        except ImportError:
            logger.warning("pipeline_contract module unavailable — using basic phase tracking")
            self._phase_enum = None
            self._phase_partition = {}

        self.pipeline = {
            "phase": "init",  # current granular phase
            "partition": "recon",  # high-level partition for dashboard
            "events": [],  # chronological event log
            "recon": {"status": "pending", "data": {}},
            "scan": {"status": "pending", "data": {}},
            "exploit": {"status": "pending", "data": {}},
            "collect": {"status": "pending", "data": {}},
        }
        self.attack_router = None
        self._ws_callback = None  # WebSocket event callback (set by web app)

        # Initialize evasion engine
        try:
            from utils.evasion import EvasionEngine

            self.evasion = EvasionEngine(config.get("evasion", "none"))
        except Exception as exc:
            logger.debug("Evasion engine unavailable: %s", exc)
            self.evasion = None

        # Initialize requester
        from utils.requester import Requester

        self.requester = Requester(config)

        # Initialize database
        try:
            from utils.database import Database

            self.db = Database()
        except Exception as exc:
            logger.debug("Database unavailable: %s", exc)
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

        # Local LLM reference (set by main.py when --local-llm is active)
        self.local_llm = None

        # --- Production components (audit, compliance, notifications, tools, plugins) ---
        try:
            from core.audit_logger import AuditLogger

            self.audit = AuditLogger()
        except Exception as exc:
            logger.debug("Audit logger unavailable: %s", exc)
            self.audit = None

        try:
            from core.compliance import ComplianceEngine

            self.compliance = ComplianceEngine()
        except Exception as exc:
            logger.debug("Compliance engine unavailable: %s", exc)
            self.compliance = None

        try:
            from core.notification import NotificationManager

            self.notifications = NotificationManager()
        except Exception as exc:
            logger.debug("Notification manager unavailable: %s", exc)
            self.notifications = None

        try:
            from core.tool_integrator import ToolIntegrator

            self.tools = ToolIntegrator()
        except Exception as exc:
            logger.debug("Tool integrator unavailable: %s", exc)
            self.tools = None

        try:
            from core.recon_arsenal import ReconArsenal

            self.recon_arsenal = ReconArsenal()
        except Exception as exc:
            logger.debug("Recon arsenal unavailable: %s", exc)
            self.recon_arsenal = None

        try:
            from core.plugin_system import PluginManager

            self.plugins = PluginManager()
            self.plugins.load_all()
        except Exception as exc:
            logger.debug("Plugin system unavailable: %s", exc)
            self.plugins = None

        # Initialize modules
        self._modules = {}
        self._load_modules()

    def _load_modules(self):
        """Load enabled scanning modules"""
        module_map = {
            "sqli": ("modules.sqli", "SQLiModule"),
            "xss": ("modules.xss", "XSSModule"),
            "lfi": ("modules.lfi", "LFIModule"),
            "cmdi": ("modules.cmdi", "CommandInjectionModule"),
            "ssrf": ("modules.ssrf", "SSRFModule"),
            "ssti": ("modules.ssti", "SSTIModule"),
            "xxe": ("modules.xxe", "XXEModule"),
            "idor": ("modules.idor", "IDORModule"),
            "nosql": ("modules.nosqli", "NoSQLModule"),
            "cors": ("modules.cors", "CORSModule"),
            "jwt": ("modules.jwt", "JWTModule"),
            "upload": ("modules.uploader", "ShellUploader"),
            "open_redirect": ("modules.open_redirect", "OpenRedirectModule"),
            "crlf": ("modules.crlf", "CRLFModule"),
            "hpp": ("modules.hpp", "HPPModule"),
            "graphql": ("modules.graphql", "GraphQLModule"),
            "proto_pollution": ("modules.proto_pollution", "ProtoPollutionModule"),
            "race_condition": ("modules.race_condition", "RaceConditionModule"),
            "websocket": ("modules.websocket", "WebSocketModule"),
            "deserialization": ("modules.deserialization", "DeserializationModule"),
            "osint": ("modules.osint", "OSINTModule"),
            "fuzzer": ("modules.fuzzer", "FuzzerModule"),
            "cloud_scan": ("modules.cloud_scanner", "CloudScannerModule"),
        }

        modules_config = self.config.get("modules", {})
        for key, (module_path, class_name) in module_map.items():
            if modules_config.get(key, False):
                try:
                    mod = __import__(module_path, fromlist=[class_name])
                    cls = getattr(mod, class_name)
                    self._modules[key] = cls(self)
                except Exception as e:
                    print(f"{Colors.warning(f'Module {key} failed to load: {e}')}")

    # ------------------------------------------------------------------
    # Pipeline event system (3-partition tracking)
    # ------------------------------------------------------------------

    def emit_pipeline_event(self, event_type: str, data: dict = None):
        """Record a pipeline event for live dashboard tracking.

        Event types include: phase_start, phase_end, finding_new,
        exploit_start, exploit_result, shell_uploaded, data_collected, etc.
        """
        event = {
            "type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data or {},
        }
        self.pipeline["events"].append(event)
        # Cap events list to prevent memory bloat
        if len(self.pipeline["events"]) > 500:
            self.pipeline["events"] = self.pipeline["events"][-500:]
        # Push to WebSocket if callback is set
        if self._ws_callback:
            try:
                self._ws_callback("pipeline_event", event)
            except Exception as exc:
                logger.debug("WebSocket callback failed: %s", exc)

    def get_pipeline_state(self) -> dict:
        """Return the current pipeline state for the dashboard."""
        attack_routes = None
        if getattr(self, "attack_router", None) is not None:
            try:
                attack_routes = self.attack_router.get_pipeline_state()
            except Exception as exc:
                if self.config.get("verbose"):
                    print(f"{Colors.warning(f'Attack router state error: {exc}')}")
                attack_routes = None

        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "phase": self.pipeline["phase"],
            "recon": self.pipeline["recon"],
            "scan": self.pipeline["scan"],
            "exploit": self.pipeline["exploit"],
            "collect": self.pipeline["collect"],
            "findings_count": len(self.findings),
            "events": self.pipeline["events"][-50:],
            "attack_routes": attack_routes,
        }

    def _run_external_tools_auto(self, target: str):
        """Run integrated external tools automatically when enabled."""
        if not self.config.get("auto_external_tools", False):
            return
        if not self.tools:
            return

        from urllib.parse import urlparse

        domain = urlparse(target).hostname or ""
        all_results = {}

        try:
            all_results.update(self.tools.run_recon_suite(target, domain=domain))
        except Exception as exc:
            if self.config.get("verbose"):
                print(f"{Colors.warning(f'External recon suite error: {exc}')}")

        try:
            all_results.update(self.tools.run_vuln_scan(target))
        except Exception as exc:
            if self.config.get("verbose"):
                print(f"{Colors.warning(f'External vuln suite error: {exc}')}")

        if all_results:
            results = [res for res in all_results.values() if hasattr(res, "success")]
            self.emit_pipeline_event(
                "external_tools_completed",
                {
                    "tools": list(all_results.keys()),
                    "success_count": sum(1 for r in results if r.success),
                    "failure_count": sum(1 for r in results if not r.success),
                },
            )

    def scan(self, target: str):
        """Scan a target URL.

        Follows the CORE FLOW:
        §1 Scope → §2 Discover → §3 Extract/Classify → §4 Context →
        §5 Prioritize → §6 Baseline → §7 Test → §8 Analyze →
        §9 Verify → Report → Learn → Adapt
        """
        self.target = target
        self.start_time = datetime.now(timezone.utc)

        # ── Audit & Notifications: scan started ──────────────────────
        if self.audit:
            self.audit.log_scan("scan.started", target=target, details={"scan_id": self.scan_id})
        if self.notifications:
            self.notifications.notify_scan_started(self.scan_id, target)

        print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
        print(f"{Colors.CYAN}  Scanning: {target}{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*60}{Colors.RESET}\n")

        # ── PIPELINE: Phase 1 - Recon & Scan ─────────────────────────
        self.pipeline["phase"] = "recon"
        self.pipeline["recon"]["status"] = "running"
        self.emit_pipeline_event("phase_start", {"phase": "recon", "target": target})

        # ── §1. SCOPE & POLICY ENGINE ────────────────────────────────
        self.scope.set_target_scope(target)
        self.scope.load_robots_txt(target)

        # Test connection
        if not self.requester.test_connection(target):
            print(f"{Colors.error(f'Cannot connect to {target}')}")
            return

        # Tech fingerprinting on initial response
        init_resp = None
        try:
            init_resp = self.requester.request(target, "GET")
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

        modules_config = self.config.get("modules", {})
        self._run_external_tools_auto(target)

        # ── PHASE 1: SHIELD DETECTION (CDN + WAF) ────────────────────
        shield_profile = None
        if modules_config.get("shield_detect", False):
            try:
                from core.shield_detector import ShieldDetector

                shield = ShieldDetector(self)
                probe_result = {
                    "response": init_resp,
                    "reachable": True,
                    "latency": 0,
                }
                shield_profile = shield.run(target, probe_result)
                self.emit_pipeline_event(
                    "shield_detection",
                    {
                        "cdn_detected": shield_profile.get("cdn", {}).get("detected", False),
                        "waf_detected": shield_profile.get("waf", {}).get("detected", False),
                        "cdn_provider": shield_profile.get("cdn", {}).get("provider"),
                        "waf_provider": shield_profile.get("waf", {}).get("provider"),
                    },
                )
            except Exception as e:
                if self.config.get("verbose"):
                    print(f"{Colors.error(f'Shield detection error: {e}')}")

        # ── PHASE 2: REAL IP DISCOVERY ────────────────────────────────
        real_ip_result = None
        if modules_config.get("real_ip", False):
            needs_discovery = True
            if shield_profile:
                needs_discovery = shield_profile.get("needs_origin_discovery", False)
            if needs_discovery:
                try:
                    from core.real_ip_scanner import RealIPScanner

                    real_ip = RealIPScanner(self)
                    real_ip_result = real_ip.run(target, shield_profile)
                    self.emit_pipeline_event(
                        "real_ip_discovery",
                        {
                            "origin_ip": real_ip_result.get("origin_ip"),
                            "confidence": real_ip_result.get("confidence"),
                            "method": real_ip_result.get("method"),
                            "candidates": len(real_ip_result.get("all_candidates", [])),
                        },
                    )
                except Exception as e:
                    if self.config.get("verbose"):
                        print(f"{Colors.error(f'Real IP discovery error: {e}')}")

        # ── Determine effective scan target using origin IP ──────────────
        # When Phase 2 discovered a real origin IP behind CDN/WAF, build
        # a URL that points directly at the origin server so that
        # crawling, fuzzing, and recon bypass the CDN/WAF layer.
        origin_ip = real_ip_result.get("origin_ip") if real_ip_result else None
        effective_target = target
        if origin_ip:
            from utils.helpers import build_origin_target

            effective_target = build_origin_target(target, origin_ip)

        # ── PHASE 5: PASSIVE RECON & DISCOVERY (fan-out) ───────────────
        # This replaces the individual recon/port/crawl/discovery calls
        # with a unified fan-out that merges all URL sources.
        fanout_result = None
        if modules_config.get("passive_recon", False):
            try:
                from core.passive_recon import PassiveReconFanout

                fanout = PassiveReconFanout(self)
                fanout_result = fanout.run(effective_target)
                urls = fanout_result.urls
                forms = fanout_result.forms
                parameters = fanout_result.params
                self.emit_pipeline_event("phase5_result", fanout_result.to_dict())
            except Exception as e:
                if self.config.get("verbose"):
                    print(f"{Colors.error(f'Phase 5 fan-out error: {e}')}")
                fanout_result = None

        # Fallback: if Phase 5 fan-out didn't run, use legacy discovery path
        if fanout_result is None:
            # ── §2. DISCOVERY & GRAPH ENGINE (legacy path) ───────────
            # Reconnaissance (optional)
            if modules_config.get("recon", False):
                try:
                    from modules.reconnaissance import ReconModule

                    recon = ReconModule(self)
                    recon.run(target)
                except Exception as e:
                    if self.config.get("verbose"):
                        print(f"{Colors.error(f'Recon error: {e}')}")

            # Port scanning: use effective_target (origin IP) for accuracy
            port_spec = modules_config.get("ports")
            port_results = []
            if port_spec:
                try:
                    from modules.port_scanner import PortScanner

                    scanner = PortScanner(self)
                    hostname = urlparse(effective_target).hostname
                    port_results = scanner.run(hostname, port_spec)
                except Exception as e:
                    if self.config.get("verbose"):
                        print(f"{Colors.error(f'Port scan error: {e}')}")

            # Scapy network crawl (SYN scan + UDP + OS fingerprint)
            scapy_results = {}
            if modules_config.get("scapy", False) or modules_config.get("scapy_crawl", False):
                try:
                    from modules.scapy_crawler import ScapyCrawler, is_scapy_available

                    if is_scapy_available():
                        scapy = ScapyCrawler(self)
                        hostname = urlparse(effective_target).hostname
                        scapy_results = scapy.run(
                            hostname,
                            port_spec,
                            syn_scan=True,
                            udp_scan=True,
                            os_detect=True,
                            traceroute=modules_config.get("traceroute", False),
                        )
                        # Merge Scapy TCP results into port_results for exploit matching
                        scapy_ports = scapy.to_port_scanner_format(scapy_results)
                        existing = {r["port"] for r in port_results}
                        for sp in scapy_ports:
                            if sp["port"] not in existing:
                                port_results.append(sp)
                    elif self.config.get("verbose"):
                        print(f"{Colors.info('scapy not installed — Scapy crawl skipped')}")
                except Exception as e:
                    if self.config.get("verbose"):
                        print(f"{Colors.error(f'Scapy crawl error: {e}')}")

            # Stealth scan (FIN/XMAS/NULL) via Scapy
            if modules_config.get("stealth_scan", False):
                try:
                    from modules.scapy_crawler import StealthPortScanner, is_scapy_available

                    if is_scapy_available():
                        stealth = StealthPortScanner(self)
                        hostname = urlparse(effective_target).hostname
                        stealth.run(hostname)
                except Exception as e:
                    if self.config.get("verbose"):
                        print(f"{Colors.error(f'Stealth scan error: {e}')}")

            # ARP network discovery (LAN host enumeration)
            if modules_config.get("arp_discovery", False):
                try:
                    from modules.scapy_crawler import ARPNetworkDiscovery, is_scapy_available

                    if is_scapy_available():
                        arp = ARPNetworkDiscovery(self)
                        subnet = modules_config.get("subnet", "")
                        if subnet:
                            arp.discover(subnet)
                except Exception as e:
                    if self.config.get("verbose"):
                        print(f"{Colors.error(f'ARP discovery error: {e}')}")

            # DNS recon (zone transfer + subdomain brute-force)
            if modules_config.get("dns_recon", False):
                try:
                    from modules.scapy_crawler import DNSReconScanner

                    dns_recon = DNSReconScanner(self)
                    domain = urlparse(target).hostname or urlparse(target).netloc
                    dns_recon.run(domain)
                except Exception as e:
                    if self.config.get("verbose"):
                        print(f"{Colors.error(f'DNS recon error: {e}')}")

            # Network exploit scanning (runs after port scan)
            if port_results and modules_config.get("net_exploit", False):
                try:
                    from modules.network_exploits import NetworkExploitScanner

                    net_exploit = NetworkExploitScanner(self)
                    hostname = urlparse(effective_target).hostname
                    net_exploit.run(hostname, port_results)
                except Exception as e:
                    if self.config.get("verbose"):
                        print(f"{Colors.error(f'Network exploit scan error: {e}')}")

            # Scapy packet-level vulnerability scan
            if modules_config.get("scapy_vuln_scan", False) or modules_config.get("scapy", False):
                try:
                    from modules.scapy_crawler import ScapyVulnScanner, is_scapy_available

                    if is_scapy_available():
                        vuln_scanner = ScapyVulnScanner(self)
                        hostname = urlparse(effective_target).hostname
                        vuln_scanner.run(
                            hostname,
                            port_results=port_results,
                            os_guess=scapy_results.get("os_guess", "") if scapy_results else "",
                        )
                    elif self.config.get("verbose"):
                        print(f"{Colors.info('scapy not installed — vuln scan skipped')}")
                except Exception as e:
                    if self.config.get("verbose"):
                        print(f"{Colors.error(f'Scapy vuln scan error: {e}')}")

            # Scapy attack chain (network-layer multi-step exploitation)
            if modules_config.get("scapy_attack_chain", False):
                try:
                    from modules.scapy_crawler import ScapyAttackChain, is_scapy_available

                    if is_scapy_available():
                        chain = ScapyAttackChain(self)
                        hostname = urlparse(effective_target).hostname
                        chain.run(
                            hostname,
                            port_results=port_results,
                            scapy_results=scapy_results,
                        )
                    elif self.config.get("verbose"):
                        print(f"{Colors.info('scapy not installed — attack chain skipped')}")
                except Exception as e:
                    if self.config.get("verbose"):
                        print(f"{Colors.error(f'Scapy attack chain error: {e}')}")

            # Technology exploit scanning
            if modules_config.get("tech_exploit", False):
                try:
                    from modules.tech_exploits import TechExploitScanner

                    tech_exploit = TechExploitScanner(self)
                    tech_exploit.run(target)
                except Exception as e:
                    if self.config.get("verbose"):
                        print(f"{Colors.error(f'Technology exploit scan error: {e}')}")

            # Crawl target (uses origin IP to bypass WAF/CDN)
            from utils.crawler import Crawler

            crawler = Crawler(self)
            depth = min(
                self.config.get("depth", 3) + self.adaptive.get_depth_boost(),
                Config.MAX_DEPTH,
            )

            if effective_target != target:
                origin_host = urlparse(effective_target).hostname or "origin"
                print(f"{Colors.info(f'Crawling via origin IP ({origin_host}) with depth {depth}...')}")
            else:
                print(f"{Colors.info(f'Crawling with depth {depth}...')}")
            urls, forms, parameters = crawler.crawl(effective_target, depth)
            print(f"{Colors.info(f'Found {len(urls)} URLs, {len(forms)} forms, {len(parameters)} parameters')}")

            # Print graph summary if verbose
            if self.config.get("verbose") and crawler.endpoint_graph:
                print(f"{Colors.info('Endpoint graph:')}")
                print(crawler.get_graph_summary())

            # Scope filter: remove out-of-scope URLs
            urls = self.scope.filter_urls(urls)
            parameters = self.scope.filter_parameters(parameters)

            # ── Fuzzer discovery (uses origin IP target) ──────────────
            if modules_config.get("fuzzer", False) or modules_config.get("discovery", False):
                try:
                    from modules.fuzzer import FuzzerModule

                    fuzzer = FuzzerModule(self)
                    fuzz_result = fuzzer.discover(effective_target)

                    for fuzz_url in fuzz_result.get("urls", set()):
                        if self.scope.is_in_scope(fuzz_url):
                            urls.add(fuzz_url)
                            self.adaptive.add_new_endpoint(fuzz_url)

                    fuzz_params = fuzz_result.get("parameters", [])
                    if fuzz_params:
                        parameters.extend(fuzz_params)
                        print(f"{Colors.info(f'Fuzzer discovered {len(fuzz_params)} additional parameters')}")
                except Exception as e:
                    if self.config.get("verbose"):
                        print(f"{Colors.error(f'Fuzzer discovery error: {e}')}")

            # Target discovery & enumeration
            if modules_config.get("discovery", False):
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
                                        parameters.append((ep, "get", name, val, "discovery"))
                except Exception as e:
                    if self.config.get("verbose"):
                        print(f"{Colors.error(f'Discovery error: {e}')}")

        # ── §3. INPUT EXTRACTION & CLASSIFICATION ────────────────────
        # ── §4. CONTEXT INTELLIGENCE ─────────────────────────────────
        enriched_params = self.context.analyze_parameters(parameters)

        # ── PHASE 6: INTELLIGENCE ENRICHMENT ──────────────────────────
        intel_bundle = None
        if modules_config.get("enrich", False):
            try:
                from core.intelligence_enricher import IntelligenceEnricher

                enricher = IntelligenceEnricher(self)
                responses = [init_resp] if init_resp else []
                intel_bundle = enricher.run(
                    responses=responses,
                    params=parameters,
                    urls=urls,
                )
                self.emit_pipeline_event("phase6_result", intel_bundle.to_dict())
            except Exception as e:
                if self.config.get("verbose"):
                    print(f"{Colors.error(f'Phase 6 enrichment error: {e}')}")

        # ── PHASE 7: ATTACK SURFACE PRIORITIZATION ───────────────────
        scan_queue = None
        if modules_config.get("enrich", False) and intel_bundle:
            try:
                from core.scan_priority_queue import ScanPriorityQueue

                pq = ScanPriorityQueue(self)
                origin_ip = real_ip_result.get("origin_ip") if real_ip_result else None
                bypass_profile = shield_profile.get("waf", {}) if shield_profile else None
                asset_graph = (
                    fanout_result
                    and hasattr(fanout_result, "_asset_graph")
                    and getattr(fanout_result, "_asset_graph", None)
                )
                scan_queue = pq.build(
                    enriched_params=enriched_params,
                    urls=urls,
                    intel_bundle=intel_bundle,
                    agent_result=None,
                    asset_graph=asset_graph,
                    bypass_profile=bypass_profile,
                    origin_ip=origin_ip,
                )
                self.emit_pipeline_event(
                    "phase7_result",
                    {
                        "queue_size": len(scan_queue),
                    },
                )
            except Exception as e:
                if self.config.get("verbose"):
                    print(f"{Colors.error(f'Phase 7 prioritization error: {e}')}")
                scan_queue = None

        # ── PIPELINE: Recon complete, transition to Scan phase ────────
        self.pipeline["recon"]["status"] = "completed"
        self.pipeline["recon"]["data"] = {
            "urls": len(urls),
            "forms": len(forms),
            "parameters": len(parameters),
        }
        self.pipeline["phase"] = "scan"
        self.pipeline["scan"]["status"] = "running"
        self.emit_pipeline_event(
            "phase_start",
            {
                "phase": "scan",
                "urls": len(urls),
                "parameters": len(enriched_params),
                "modules": list(self._modules.keys()),
            },
        )

        # ── AI: Predict vulnerabilities and build attack strategy ─────
        ai_strategy = self.ai.get_attack_strategy(target, enriched_params)
        if self.config.get("verbose") and ai_strategy["module_order"]:
            module_order = ai_strategy["module_order"]
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
                    ep["url"],
                    ep["method"],
                    ep["param"],
                    ep["value"],
                )

        # ── §7. ADAPTIVE TESTING (AI-driven module selection) ────────
        # Determine module execution order via AI strategy
        ordered_modules = []
        if ai_strategy["module_order"]:
            for mkey in ai_strategy["module_order"]:
                if mkey in self._modules:
                    ordered_modules.append((mkey, self._modules[mkey]))
            # Append any remaining modules not in AI order
            for mkey, minst in self._modules.items():
                if mkey not in ai_strategy["module_order"]:
                    ordered_modules.append((mkey, minst))
        else:
            ordered_modules = list(self._modules.items())

        # ── Reflection Gate ──────────────────────────────────────────
        # Modules that only make sense when user input is reflected in
        # the response body.  If no reflection is detected for a param,
        # these modules are skipped to avoid useless payload spam.
        REFLECTION_DEPENDENT_MODULES = {"xss", "ssti"}
        reflection_cache = {}  # (url, method, param) → bool

        for ep in enriched_params:
            r_key = (ep["url"], ep["method"], ep["param"])
            if r_key not in reflection_cache:
                reflection_cache[r_key] = self.baseline_engine.reflection_check(
                    ep["url"],
                    ep["method"],
                    ep["param"],
                    ep["value"],
                )

        reflected_count = sum(1 for v in reflection_cache.values() if v)
        skipped_count = len(reflection_cache) - reflected_count
        if skipped_count > 0:
            print(
                f"{Colors.info(f'Reflection gate: {reflected_count} reflected, {skipped_count} non-reflected (XSS/SSTI skipped)')}"
            )

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
                    r_key = (ep["url"], ep["method"], ep["param"])
                    if not reflection_cache.get(r_key, False):
                        self.persistence.mark_tested(ep_key)
                        continue

                def _do_test(m=module_instance, e=ep):
                    self.scope.enforce_rate_limit()
                    delay = self.adaptive.get_delay()
                    if delay > 0:
                        time.sleep(delay)
                    if hasattr(m, "test"):
                        m.test(e["url"], e["method"], e["param"], e["value"])
                    return True

                self.persistence.execute_with_retry(_do_test, ep_key)

            # URL-level checks (CORS, JWT, etc.) — in priority order
            for url_item, _score in prioritized_urls:
                url_key = f"{module_key}:url:{url_item}"
                if self.persistence.is_tested(url_key):
                    continue

                def _do_url_test(m=module_instance, u=url_item):
                    if hasattr(m, "test_url"):
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
        while (
            self.adaptive.should_rediscover()
            and modules_config.get("discovery", False)
            and rediscovery_count < MAX_REDISCOVERY_ROUNDS
        ):
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
                                new_params.append((ep_url, "get", name, val, "adaptive"))
                self.adaptive.new_endpoints.clear()  # reset after processing
                if new_params:
                    new_enriched = self.context.analyze_parameters(new_params)
                    new_enriched = self.prioritizer.prioritize_parameters(new_enriched)
                    for module_key, module_instance in self._modules.items():
                        for ep in new_enriched:
                            try:
                                if hasattr(module_instance, "test"):
                                    module_instance.test(
                                        ep["url"],
                                        ep["method"],
                                        ep["param"],
                                        ep["value"],
                                    )
                            except Exception:
                                pass
            except Exception as e:
                if self.config.get("verbose"):
                    print(f"{Colors.error(f'Adaptive re-scan error: {e}')}")
                break

        # ── PHASE 8: VULNERABILITY SCAN WORKERS ─────────────────────
        # If Phase 7 produced a scan queue, run it through the worker pool
        if scan_queue:
            try:
                from core.scan_worker_pool import ScanWorkerPool

                worker_pool = ScanWorkerPool(self)
                worker_pool.run(scan_queue)
                self.emit_pipeline_event(
                    "phase8_result",
                    {
                        "additional_findings": len(self.findings),
                    },
                )
            except Exception as e:
                if self.config.get("verbose"):
                    print(f"{Colors.error(f'Phase 8 worker pool error: {e}')}")

        # ── PHASE 9: POST-WORKER VERIFICATION ────────────────────────
        verification_result = None
        if modules_config.get("chain_detect", False) and self.findings:
            try:
                from core.post_worker_verifier import PostWorkerVerifier

                pwv = PostWorkerVerifier(self)
                self._shield_profile = shield_profile  # expose for WAF check
                verification_result = pwv.run(self.findings)
                self.findings = verification_result.verified_findings

                # Emit chain detection results
                if verification_result.exploit_chains:
                    self.emit_pipeline_event(
                        "exploit_chains_detected",
                        {
                            "chain_count": len(verification_result.exploit_chains),
                            "chains": [c.to_dict() for c in verification_result.exploit_chains],
                        },
                    )
                    # Print chains
                    for chain in verification_result.exploit_chains:
                        print(f"\n  {Colors.RED}{Colors.BOLD}[CHAIN] {chain.name}{Colors.RESET}")
                        print(f"    CVSS: {chain.combined_cvss}  Severity: {chain.combined_severity}")
                        print(f"    Steps: {' → '.join(chain.steps)}")
            except Exception as e:
                if self.config.get("verbose"):
                    print(f"{Colors.error(f'Phase 9 verification error: {e}')}")

        # ── PHASE 9B: EXPLOIT REFERENCE SEARCHER ─────────────────────
        if modules_config.get("exploit_search", False) and self.findings:
            try:
                from core.exploit_searcher import ExploitSearcher

                exploit_searcher = ExploitSearcher(self)
                self.findings = exploit_searcher.run(self.findings)
            except Exception as e:
                if self.config.get("verbose"):
                    print(f"{Colors.error(f'Phase 9B exploit search error: {e}')}")

        # ── PHASE 4: AGENT SCANNER (autonomous goal-driven scan) ─────
        agent_result = None
        if modules_config.get("agent_scan", False):
            try:
                from core.agent_scanner import AgentScanner

                agent = AgentScanner(self)
                waf_bypass_profile = None
                if shield_profile and shield_profile.get("needs_waf_bypass"):
                    waf_bypass_profile = shield_profile.get("waf", {})
                agent_result = agent.run(
                    target,
                    real_ip_result=real_ip_result,
                    waf_bypass_profile=waf_bypass_profile,
                )
                self.emit_pipeline_event(
                    "agent_scan_complete",
                    {
                        "goals_completed": len(agent_result.get("goals_completed", [])),
                        "goals_skipped": len(agent_result.get("goals_skipped", [])),
                        "pivots_found": len(agent_result.get("pivots_found", [])),
                        "coverage": agent_result.get("scan_coverage_pct", 0),
                    },
                )
            except Exception as e:
                if self.config.get("verbose"):
                    print(f"{Colors.error(f'Agent scanner error: {e}')}")

        # ── Post-exploitation ────────────────────────────────────────
        # ── PIPELINE: Scan complete → Exploit phase (Partition 2) ──
        self.pipeline["scan"]["status"] = "completed"
        self.pipeline["scan"]["data"] = {
            "findings": len(self.findings),
            "modules_used": list(self._modules.keys()),
        }
        self.emit_pipeline_event("phase_end", {"phase": "scan", "findings": len(self.findings)})

        # ── PIPELINE: Partition 2 - Attack Router ─────────────────
        # Route confirmed vulns to the right exploitation tool
        self.pipeline["phase"] = "exploit"
        self.pipeline["exploit"]["status"] = "running"
        self.emit_pipeline_event(
            "phase_start",
            {
                "phase": "exploit",
                "findings_to_route": len(self.findings),
            },
        )

        # AI-driven auto-exploit: orchestrates data extraction, shell
        # upload, and system enumeration based on confirmed findings.
        # Auto-attack is triggered when auto_exploit is ON, or when there
        # are HIGH/CRITICAL verified findings (smart auto-attack).
        exploitable_findings = [f for f in self.findings if f.severity in ("CRITICAL", "HIGH") and f.confidence >= 0.6]
        should_auto_attack = modules_config.get("auto_exploit", False) or (
            exploitable_findings and modules_config.get("smart_attack", True)
        )
        if should_auto_attack and self.findings:
            try:
                from core.attack_router import AttackRouter

                self.attack_router = AttackRouter(self)
                routes = self.attack_router.route(self.findings)
                self.emit_pipeline_event(
                    "routes_planned",
                    {
                        "total_routes": len(routes),
                        "families": list({r.family for r in routes}),
                    },
                )
                if routes:
                    self.post_exploit_results = self.attack_router.execute(routes)
            except Exception as e:
                if self.config.get("verbose"):
                    print(f"{Colors.error(f'Attack router error: {e}')}")
                # Fallback to direct PostExploitEngine
                try:
                    from core.post_exploit import PostExploitEngine

                    post_engine = PostExploitEngine(self)
                    self.post_exploit_results = post_engine.run(self.findings)
                except Exception as e2:
                    if self.config.get("verbose"):
                        print(f"{Colors.error(f'Post-exploitation fallback error: {e2}')}")

        # Legacy manual flags kept for backward compatibility
        if modules_config.get("shell", False) and self.findings:
            try:
                from modules.uploader import ShellUploader

                uploader = ShellUploader(self)
                uploader.run(self.findings, forms)
            except Exception as e:
                if self.config.get("verbose"):
                    print(f"{Colors.error(f'Shell upload error: {e}')}")

        if modules_config.get("dump", False) and self.findings:
            try:
                from modules.dumper import DataDumper

                dumper = DataDumper(self)
                dumper.run(self.findings)
            except Exception as e:
                if self.config.get("verbose"):
                    print(f"{Colors.error(f'Data dump error: {e}')}")

        if modules_config.get("os_shell", False) and self.findings:
            try:
                from core.os_shell import OSShellHandler

                handler = OSShellHandler(self)
                handler.run(self.findings, forms)
            except Exception as e:
                if self.config.get("verbose"):
                    print(f"{Colors.error(f'OS shell error: {e}')}")

        if modules_config.get("brute", False):
            try:
                from modules.brute_force import BruteForceModule

                bruter = BruteForceModule(self)
                bruter.run(forms)
            except Exception as e:
                if self.config.get("verbose"):
                    print(f"{Colors.error(f'Brute force error: {e}')}")

        if modules_config.get("exploit_chain", False) and self.findings:
            try:
                from core.exploit_chain import ExploitChainEngine

                chainer = ExploitChainEngine(self)
                chainer.run(self.findings)
            except Exception as e:
                if self.config.get("verbose"):
                    print(f"{Colors.error(f'Exploit chain error: {e}')}")

        # ── PIPELINE: Exploit phase complete → Collect phase ──────
        self.pipeline["exploit"]["status"] = "completed"
        self.pipeline["exploit"]["data"] = {
            "results": len(self.post_exploit_results) if self.post_exploit_results else 0,
            "attack_routes": (self.attack_router.get_pipeline_state()["total_routes"] if self.attack_router else 0),
        }
        self.emit_pipeline_event("phase_end", {"phase": "exploit"})

        # ── PIPELINE: Partition 3 - Data Collection ──────────────
        self.pipeline["phase"] = "collect"
        self.pipeline["collect"]["status"] = "running"
        self.emit_pipeline_event("phase_start", {"phase": "collect"})

        self.end_time = datetime.now(timezone.utc)

        # ── Clear persistence progress on complete scan ───────────────
        self.persistence.clear_progress()

        # ── PHASE 10: COMMIT & REPORT ─────────────────────────────────
        # Collect chain/shield/agent data produced during previous phases
        # and pass them to the unified OutputPhase for DB commit + reports.
        exploit_chains = []
        if verification_result and hasattr(verification_result, "exploit_chains"):
            exploit_chains = verification_result.exploit_chains

        # Store enrichment data for generate_reports() backward compatibility
        self._exploit_chains = exploit_chains
        self._origin_result = real_ip_result
        self._agent_result = agent_result

        try:
            from core.output_phase import OutputPhase

            output_phase = OutputPhase(self)
            output_phase.run(
                verified_findings=self.findings,
                exploit_chains=exploit_chains,
                shield_profile=shield_profile,
                origin_result=real_ip_result,
                agent_result=agent_result,
                report_format=self.config.get("format", "html"),
            )
        except Exception as exc:
            if self.config.get("verbose"):
                print(f"{Colors.error(f'Phase 10 output error: {exc}')}")
            # Fallback: legacy DB update
            if self.db:
                try:
                    self.db.update_scan(
                        self.scan_id,
                        end_time=self.end_time,
                        findings_count=len(self.findings),
                        total_requests=self.requester.total_requests,
                    )
                except Exception as e:
                    if self.config.get("verbose"):
                        print(f"{Colors.warning(f'Could not update scan record: {e}')}")

        # ── PHASE 11: ATTACK MAP (exploit-aware) ─────────────────────
        attack_map_result = None
        if modules_config.get("attack_map", False) and self.findings:
            # Defense-in-depth: main.py enforces this dependency for CLI,
            # but engine can also be invoked programmatically (web API).
            if not modules_config.get("exploit_search", False):
                try:
                    from core.exploit_searcher import ExploitSearcher

                    exploit_searcher = ExploitSearcher(self)
                    self.findings = exploit_searcher.run(self.findings)
                except Exception as e:
                    if self.config.get("verbose"):
                        print(f"{Colors.warning(f'Phase 9B auto-enable for attack map failed: {e}')}")
            try:
                from core.attack_map import AttackMapBuilder

                map_builder = AttackMapBuilder(self)
                attack_map_result = map_builder.run(
                    self.findings,
                    exploit_chains=exploit_chains,
                )
                self._attack_map = attack_map_result
                self.emit_pipeline_event(
                    "attack_map_complete",
                    {
                        "total_nodes": attack_map_result.get("summary", {}).get("total_nodes", 0),
                        "critical_paths": attack_map_result.get("summary", {}).get("critical_paths", 0),
                        "zero_click_paths": attack_map_result.get("summary", {}).get("zero_click_paths", 0),
                    },
                )
            except Exception as e:
                if self.config.get("verbose"):
                    print(f"{Colors.error(f'Phase 11 attack map error: {e}')}")

        # ── PIPELINE: All phases complete ─────────────────────────
        self.pipeline["collect"]["status"] = "completed"
        self.pipeline["collect"]["data"] = {
            "total_findings": len(self.findings),
            "total_requests": self.requester.total_requests,
            "exploit_results": len(self.post_exploit_results) if self.post_exploit_results else 0,
            "metrics": self.requester.metrics.summary() if hasattr(self.requester, "metrics") else {},
        }
        self.pipeline["phase"] = "done"
        self.emit_pipeline_event("phase_end", {"phase": "collect"})
        self.emit_pipeline_event(
            "pipeline_complete",
            {
                "findings": len(self.findings),
                "duration": str(self.end_time - self.start_time) if self.start_time else "",
            },
        )

        # ── Print summary ────────────────────────────────────────────
        self._print_summary()

        # ── Audit & Notifications: scan completed ────────────────────
        if self.audit:
            self.audit.log_scan(
                "scan.completed",
                target=target,
                details={
                    "scan_id": self.scan_id,
                    "findings": len(self.findings),
                    "duration": str(self.end_time - self.start_time) if self.start_time else "",
                },
            )
        if self.notifications:
            self.notifications.notify_scan_completed(self.scan_id, target, len(self.findings))
            # Notify for each critical finding
            for f in self.findings:
                if getattr(f, "severity", "") == "CRITICAL":
                    self.notifications.notify_critical_finding(f.technique, target, scan_id=self.scan_id)

        # ── Compliance mapping (auto-run if findings exist) ──────────
        self._compliance_report = None
        if self.compliance and self.findings:
            try:
                self._compliance_report = self.compliance.analyze(self.findings, scan_id=self.scan_id, target=target)
            except Exception:
                pass

        # ── Plugin hooks: post_scan ──────────────────────────────────
        if self.plugins:
            try:
                self.plugins.fire_hook("post_scan", engine=self, findings=self.findings)
            except Exception:
                pass

    def _enrich_finding_signals(self):
        """Run multi-signal analysis on existing findings to refine confidence."""
        for finding in self.findings:
            baseline = self.baseline_engine.get_baseline(
                finding.url,
                finding.method,
                finding.param,
                "",
            )
            signals = self.scorer.analyze(
                baseline=baseline,
                elapsed=0,
                response_text=finding.evidence,
                payload=finding.payload,
                error_patterns=["error", "syntax", "exception", "warning"],
                baseline_text="",
            )
            finding.signals = signals.to_dict()
            # Boost confidence if multi-signal analysis agrees
            if signals.combined_score > finding.confidence:
                finding.confidence = signals.combined_score

    def add_finding(self, finding: Finding):
        """Add a vulnerability finding"""
        # Validate finding has minimum required fields
        if not finding.technique or not finding.url:
            if self.config.get("verbose"):
                print(f"{Colors.warning('Skipping invalid finding: missing technique or url')}")
            return

        # Skip duplicate findings (same technique + url + param)
        for existing in self.findings:
            if (
                existing.technique == finding.technique
                and existing.url == finding.url
                and existing.param == finding.param
            ):
                return

        self.findings.append(finding)

        # Emit pipeline event for live dashboard
        self.emit_pipeline_event(
            "finding_new",
            {
                "technique": finding.technique,
                "severity": finding.severity,
                "url": finding.url,
                "param": finding.param,
                "confidence": finding.confidence,
            },
        )

        # Print finding
        severity_color = {
            "CRITICAL": Colors.RED + Colors.BOLD,
            "HIGH": Colors.RED,
            "MEDIUM": Colors.YELLOW,
            "LOW": Colors.CYAN,
            "INFO": Colors.BLUE,
        }.get(finding.severity, Colors.WHITE)

        print(f"\n  {severity_color}[{finding.severity}]{Colors.RESET} {finding.technique}")
        print(f"    URL:     {finding.url}")
        if finding.param:
            print(f"    Param:   {finding.param}")
        if finding.payload:
            payload_display = finding.payload[:80] + "..." if len(finding.payload) > 80 else finding.payload
            print(f"    Payload: {payload_display}")
        if finding.evidence:
            print(f"    Evidence: {finding.evidence[:100]}")

        # Save to database
        if self.db:
            self.db.save_finding(self.scan_id, finding)

        # LLM real-time enrichment: attach AI analysis to high-severity findings.
        # Only runs when --local-llm is active; skipped during high-volume scans
        # to avoid slowing down the scan loop.
        if (
            self.local_llm
            and self.local_llm.is_loaded
            and finding.severity in ("CRITICAL", "HIGH")
            and self.config.get("local_llm")
        ):
            try:
                fd = {
                    "technique": finding.technique,
                    "url": finding.url,
                    "param": finding.param or "",
                    "payload": finding.payload or "",
                    "evidence": finding.evidence or "",
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                }
                analysis = self.local_llm.analyze_finding(fd)
                if analysis.get("llm_analysis"):
                    finding.llm_analysis = analysis["llm_analysis"]
                    if not self.config.get("quiet"):
                        print(f"    {Colors.CYAN}[AI]{Colors.RESET} {analysis['llm_analysis'][:120]}")
            except Exception:
                pass

    def _print_attack_results(self):
        """Display rich attack/exploitation results in the console."""
        if not self.post_exploit_results:
            return

        # Determine data source: attack_router provides structured route dicts,
        # otherwise post_exploit_results is a list of PostExploitResult.
        results = self.post_exploit_results
        if not results:
            return

        print(f"\n  {Colors.RED}{Colors.BOLD}━━━ Attack / Exploitation Results ━━━{Colors.RESET}")

        # Route-based results (from AttackRouter) are dicts
        if isinstance(results[0], dict):
            successful = [r for r in results if r.get("status") == "completed"]
            failed = [r for r in results if r.get("status") == "failed"]
            print(
                f"    Total routes: {len(results)}  |  "
                f"{Colors.GREEN}Successful: {len(successful)}{Colors.RESET}  |  "
                f"{Colors.RED}Failed: {len(failed)}{Colors.RESET}"
            )

            for route in results:
                icon = route.get("icon", "🔧")
                label = route.get("label", route.get("family", "Unknown"))
                status = route.get("status", "unknown")
                technique = route.get("technique", "")
                url = route.get("url", "")
                severity = route.get("severity", "")

                if status == "completed":
                    status_str = f"{Colors.GREEN}✓ SUCCESS{Colors.RESET}"
                elif status == "failed":
                    status_str = f"{Colors.RED}✗ FAILED{Colors.RESET}"
                else:
                    status_str = f"{Colors.YELLOW}⏳ {status.upper()}{Colors.RESET}"

                print(f"\n    {icon} {Colors.BOLD}{label}{Colors.RESET}")
                print(f"      Status:    {status_str}")
                print(f"      Target:    {url}")
                if technique:
                    print(f"      Technique: {technique}")
                if severity:
                    sev_color = {
                        "CRITICAL": Colors.RED + Colors.BOLD,
                        "HIGH": Colors.RED,
                        "MEDIUM": Colors.YELLOW,
                    }.get(severity, Colors.WHITE)
                    print(f"      Severity:  {sev_color}{severity}{Colors.RESET}")

                # Show individual action results
                for action_result in route.get("results", []):
                    action = action_result.get("action", "")
                    action_success = action_result.get("success", False)
                    data = action_result.get("data", "")
                    action_icon = "✓" if action_success else "✗"
                    action_color = Colors.GREEN if action_success else Colors.RED
                    print(f"      {action_color}{action_icon}{Colors.RESET} {action}", end="")
                    if data and action_success:
                        # Show truncated extracted data
                        data_preview = str(data)[:120]
                        print(f": {Colors.CYAN}{data_preview}{Colors.RESET}")
                    else:
                        print()
        else:
            # PostExploitResult objects
            successful = [r for r in results if r.success]
            failed = [r for r in results if not r.success]
            print(
                f"    Total actions: {len(results)}  |  "
                f"{Colors.GREEN}Successful: {len(successful)}{Colors.RESET}  |  "
                f"{Colors.RED}Failed: {len(failed)}{Colors.RESET}"
            )

            for r in results:
                icon = "✓" if r.success else "✗"
                color = Colors.GREEN if r.success else Colors.RED
                print(f"    {color}{icon}{Colors.RESET} [{r.action}] {r.finding.technique} → {r.finding.url}")
                if r.success and r.data:
                    print(f"      {Colors.CYAN}Data: {str(r.data)[:150]}{Colors.RESET}")

        print(f"  {Colors.RED}{Colors.BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")

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
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                if sev in severities:
                    print(f"    {sev}: {severities[sev]}")

        # Scope summary
        scope_summary = self.scope.get_scope_summary()
        if scope_summary["blocked_count"] > 0:
            print(f"\n  {Colors.YELLOW}Scope:{Colors.RESET} {scope_summary['blocked_count']} out-of-scope URLs blocked")

        # Tech fingerprint summary
        if self.context.detected_tech:
            print(f"  {Colors.CYAN}Detected tech:{Colors.RESET} {', '.join(sorted(self.context.detected_tech))}")

        # Adaptive intelligence summary
        adaptive_summary = self.adaptive.get_scan_summary()
        if adaptive_summary.get("waf_detected"):
            print(f"\n  {Colors.YELLOW}WAF Detected:{Colors.RESET} {adaptive_summary['waf_name']}")
        if adaptive_summary.get("block_rate", 0) > 0.1:
            print(f"  Block Rate: {adaptive_summary['block_rate']:.1%}")

        # AI Intelligence summary
        ai_summary = self.ai.get_ai_summary()
        if ai_summary["total_patterns"] > 0:
            print(f"\n  {Colors.CYAN}AI Intelligence:{Colors.RESET}")
            print(f"    Learned patterns: {ai_summary['total_patterns']}")
            print(f"    Successful techniques: {ai_summary['successful_techniques']}")

        # Persistence summary
        persist_summary = self.persistence.get_persistence_summary()
        if persist_summary["total_retries"] > 0:
            print(f"\n  {Colors.CYAN}Persistence:{Colors.RESET}")
            print(f"    Endpoints tested: {persist_summary['tested']}")
            print(f"    Total retries: {persist_summary['total_retries']}")
            print(f"    Evasion level: {persist_summary['current_evasion']}")
            if persist_summary["exhausted"] > 0:
                print(f"    Exhausted: {persist_summary['exhausted']}")

        # Performance metrics from requester
        if hasattr(self.requester, "metrics"):
            m = self.requester.metrics.summary()
            print(f"\n  {Colors.CYAN}Performance Metrics:{Colors.RESET}")
            print(f"    Throughput:     {m['requests_per_second']} req/s")
            print(f"    Avg Response:   {m['avg_response_time_ms']}ms")
            if m["cache_hits"] + m["cache_misses"] > 0:
                print(
                    f"    Cache Hit Rate: {m['cache_hit_rate']}%"
                    f" ({m['cache_hits']} hits / {m['cache_misses']} misses)"
                )
            if m["rate_limited"] > 0:
                print(f"    Rate Limited:   {m['rate_limited']} requests")
            if m["failed"] > 0:
                print(f"    Failed:         {m['failed']} requests")

        # ── Attack / Exploitation Results ─────────────────────────────────
        self._print_attack_results()

        print(f"{Colors.BOLD}{'='*60}{Colors.RESET}")

    def generate_reports(self):
        """Generate reports for the current scan.

        When Phase 10 (OutputPhase) ran inside scan(), reports are already
        generated.  This method remains for backward-compatible CLI usage
        and passes any enrichment data the engine collected.
        """
        try:
            from core.reporter import ReportGenerator

            output_dir = self.config.get("output_dir", Config.REPORTS_DIR)
            generator = ReportGenerator(
                self.scan_id,
                self.findings,
                self.target,
                self.start_time,
                self.end_time,
                self.requester.total_requests,
                output_dir=output_dir,
                exploit_chains=getattr(self, "_exploit_chains", []),
                shield_profile=getattr(self, "_shield_profile", None),
                origin_result=getattr(self, "_origin_result", None),
                agent_result=getattr(self, "_agent_result", None),
            )
            generator.generate("html")
            generator.generate("json")
        except Exception as e:
            if self.config.get("verbose"):
                print(f"{Colors.error(f'Report generation error: {e}')}")
