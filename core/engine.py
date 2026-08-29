#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK
Core Engine - Scan orchestration and module management

The canonical pipeline is defined in ``core/pipeline_contract.py``
(see :class:`Phase` and :data:`PHASE_ORDER`).  Twenty-one phases run in
strict forward order from ``init`` to ``done``; partition mapping for the
dashboard is in :data:`PHASE_PARTITION`.

For an end-to-end description of how the engine drives each phase,
see ``LOGIC_MAP.md``.
"""

import threading
import time
import uuid
import json
import logging
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, parse_qs


from config import Config, Colors, MITRE_CWE_MAP
from core.pipeline_contract import Phase
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
            "firewall bypass": "Enforce ACLs on the origin, not only the edge. Do not trust X-Forwarded-For / CF-Connecting-IP unless the hop is a known proxy. Normalize paths before matching URL rules. Restrict origin to CDN/WAF source IPs only.",
            "path acl": "Normalize and decode URLs before ACL evaluation. Match on the canonical path, not the raw request-target.",
            "ip allowlist": "Ignore client-supplied forwarding headers except from a pinned proxy CIDR. Bind allowlists to the TCP source address.",
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
        # Thread-safe writes to ``self.findings`` and the dedup lookup.
        # The worker pool ( :mod:`core.scan_worker_pool` ) dispatches
        # multiple module categories concurrently, and module tests
        # themselves spin up additional thread pools (race conditions,
        # port scanner, etc.).  All of these eventually call
        # :meth:`add_finding`, so without a lock the dedup loop reads
        # a list that another thread is mutating, which produced
        # duplicate findings, lost findings, and (rarely) ``IndexError``
        # / ``RuntimeError: list changed size during iteration``.
        self._findings_lock = threading.Lock()
        self.start_time = None
        self.end_time = None
        self.target = None
        self.post_exploit_results = []
        # Canonical findings store (populated by core.emit.emit_signal)
        self._canonical_findings: dict = {}
        # TargetSurface (populated by build_surface during scan)
        self.surface = None

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
            from core.pipeline_contract import Phase, PHASE_PARTITION, PipelineStateMachine
            self._phase_enum = Phase
            self._phase_partition = PHASE_PARTITION
            # Drive granular phase tracking through the canonical state
            # machine. ``strict=False`` so that an optional phase being
            # skipped (e.g. PLAN_DISPLAY when --show-plan is off) doesn't
            # raise; the machine still rejects backward transitions.
            self._state_machine = PipelineStateMachine(strict=False)
        except ImportError:
            logger.warning("pipeline_contract module unavailable — using basic phase tracking")
            self._phase_enum = None
            self._phase_partition = {}
            self._state_machine = None

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

        # Universal bypass orchestrator (lazy: only built when something
        # asks for it via build_orchestrator). Modules check
        # ``self.bypass`` to grab payload-variant ladders or to hook
        # extra headers onto outgoing requests. ``None`` means "no
        # bypass active"; the requester degrades to the legacy WAF
        # encodings already shipped with utils.requester.Requester.
        self.bypass = None
        # Streaming auto-exploiter (installed only when
        # --full-attack/--smart-attack and --authorized are both on).
        self.full_attacker = None

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

        # Wire the scope's rate limiter into the requester so EVERY
        # outbound HTTP request honours the configured rate limit.
        # Previously the rate limit was only enforced inside the engine
        # scan-loop, which meant module-level calls and parallel worker
        # dispatch bypassed it entirely and could hammer the target
        # well above the configured throttle.
        try:
            self.requester.attach_rate_limiter(self.scope)
        except AttributeError:
            # Older Requester implementations without the hook — nothing to do.
            pass

        # SECURITY (SEC-005): attach the centralized network policy when it
        # is active (allowed domains configured and/or private-target
        # blocking enabled).  Every request URL and redirect hop is then
        # validated inside the Requester.  Inactive policy (no constraints
        # configured) leaves behavior unchanged for operator-driven scans.
        self.net_policy = None
        try:
            from core.netpolicy import NetworkSecurityPolicy

            scope_domains = (self.config.get("scope") or {}).get("allowed_domains") or []
            policy = NetworkSecurityPolicy.from_env()
            if scope_domains and not policy.allowed_domains:
                policy = NetworkSecurityPolicy(
                    allowed_domains=list(scope_domains),
                    block_private=policy.block_private,
                )
            if policy.active:
                self.net_policy = policy
                self.requester.attach_network_policy(policy)
                logger.info(
                    "Network policy active (domains=%s, block_private=%s)",
                    sorted(policy.allowed_domains) or "-",
                    policy.block_private,
                )
        except Exception as exc:
            logger.debug("Network policy unavailable: %s", exc)

        # --- Philosophy layer (opt-in) ---
        # When config["philosophy"] is true, attach the reasoning layer
        # that adds: falsifiable hypotheses with Bayesian belief updates,
        # counterfactual A/B oracles, an HMAC-signed evidence ledger,
        # and a causal DAG over findings. See PHILOSOPHY.md.
        # Disabled by default; the engine pipeline is byte-identical
        # when off.
        self.philosophy = None
        if config.get("philosophy"):
            try:
                from core.philosophy_layer import PhilosophyLayer
                self.philosophy = PhilosophyLayer()
                logger.info("Philosophy layer enabled (hypothesis-driven reasoning + signed evidence ledger)")
            except Exception as exc:
                logger.warning("Philosophy layer failed to initialize: %s", exc)
                self.philosophy = None

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

        # ── Universal Bypass Orchestrator ─────────────────────────────
        # Activated when --full-bypass or --waf-bypass is set. Modules
        # consult ``self.bypass`` for adaptive payload variant lists
        # (pre-prioritised by per-host learning ledger) instead of
        # rolling their own one-shot encoding tables. The requester
        # also pipes outbound scan traffic through ``bypass.apply()``
        # to inject IP-spoofing / origin-spoofing headers when
        # WAF-class blocks are detected.
        if config.get("full_bypass") or config.get("waf_bypass") or config.get("firewall_bypass"):
            try:
                from core.bypass import build_orchestrator

                self.bypass = build_orchestrator(config)
                logger.debug(
                    "BypassOrchestrator active (max_attempts=%s)",
                    self.bypass.max_attempts,
                )
                # Make the orchestrator visible to the requester so
                # every outbound scan request can pick up adaptive
                # spoofing headers and jitter.
                if hasattr(self.requester, "attach_bypass"):
                    self.requester.attach_bypass(self.bypass)
            except Exception as exc:
                logger.debug("BypassOrchestrator init failed: %s", exc)
                self.bypass = None

        # ── Streaming Auto-Exploiter (Full Attacker) ──────────────────
        # Hooks into ``add_finding`` so confirmed HIGH/CRITICAL vulns
        # trigger exploitation immediately rather than waiting for the
        # end-of-scan AttackRouter pass. Gated by --authorized AND
        # one of --full-attack/--smart-attack/--auto-exploit.
        try:
            from core.full_attacker import install as _install_attacker

            self.full_attacker = _install_attacker(self)
            if self.full_attacker:
                logger.debug(
                    "FullAttacker active (severity_floor=%s, conf>=%s, max=%s)",
                    self.full_attacker.policy.severity_floor,
                    self.full_attacker.policy.confidence_threshold,
                    self.full_attacker.policy.max_exploits_per_scan,
                )
        except Exception as exc:
            logger.debug("FullAttacker install failed: %s", exc)
            self.full_attacker = None

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
            # Previously declared in CLI but missing from the module map —
            # `--full` / `--oauth` etc. silently did nothing before this fix.
            "oauth": ("modules.oauth", "OAuthModule"),
            "mfa_bypass": ("modules.mfa_bypass", "MFABypassModule"),
            "api_versioning": ("modules.api_versioning", "APIVersioningModule"),
            "dep_confusion": ("modules.dep_confusion", "DependencyConfusionModule"),
            # LLM-driven business-logic flaw scanner (--llm-logic).
            # Requires --local-llm / --llm-provider / --llm-profile to be
            # active; otherwise the module is a no-op.
            "llm_logic": ("modules.llm_logic", "LLMLogicModule"),
            # HTTP/2 smuggling, cache poisoning, API abuse modules
            "h2_smuggling": ("modules.h2_smuggling", "H2SmugglingModule"),
            "cache_poisoning": ("modules.cache_poisoning", "CachePoisoningModule"),
            "api_abuse": ("modules.api_abuse", "APIAbuseModule"),
            # Deep multi-technique scanner — module file existed but was never
            # registered here, so `--deep-scan` (and its auto-enable paths)
            # silently did nothing until now.
            "deep_scan": ("modules.deep_scan", "DeepScanModule"),
            # GateBreaker: unified WAF/auth/rate-limit gate detection and
            # bypass orchestration on top of the BypassOrchestrator ladder.
            "gatebreaker": ("modules.gatebreaker", "GateBreakerModule"),
            # Firewall Bypass: network / NGFW / ACL (path, IP, port,
            # protocol, origin hop) — complementary to WAF/GateBreaker.
            "firewall_bypass": ("modules.firewall_bypass", "FirewallBypassModule"),
            # TLS / cryptographic configuration (non-invasive) — closes the
            # TLS_CRYPTO attack-surface blind spot.
            "tls": ("modules.tls_scan", "TLSScanModule"),
            # Secrets exposure (non-invasive) — closes the SECRETS blind spot.
            "secrets": ("modules.secrets_scan", "SecretsScanModule"),
            # ── NEW: Complete coverage modules ──────────────────────────
            # Network Infrastructure
            "dns_attacks": ("modules.dns_attacks", "DNSAttackModule"),
            "snmp_enum": ("modules.snmp_enum", "SNMPEnumModule"),
            "smb_attacks": ("modules.smb_attacks", "SMBAttackModule"),
            "ssh_attacks": ("modules.ssh_attacks", "SSHAttackModule"),
            "rdp_attacks": ("modules.rdp_attacks", "RDPAttackModule"),
            "nfs_enum": ("modules.nfs_enum", "NFSEnumModule"),
            "rpc_enum": ("modules.rpc_enum", "RPCEnumModule"),
            "vnc_attacks": ("modules.vnc_attacks", "VNCAttackModule"),
            "ipv6_attacks": ("modules.ipv6_attacks", "IPv6AttackModule"),
            "vlan_hopping": ("modules.vlan_hopping", "VLANHoppingModule"),
            "vpn_attacks": ("modules.vpn_attacks", "VPNAttackModule"),
            "dhcp_attacks": ("modules.dhcp_attacks", "DHCPAttackModule"),
            "arp_attacks": ("modules.arp_attacks", "ARPAttackModule"),
            "icmp_attacks": ("modules.icmp_attacks", "ICMPAttackModule"),
            # Web Applications
            "csrf": ("modules.csrf", "CSRFModule"),
            "clickjacking": ("modules.clickjacking", "ClickjackingModule"),
            "host_header": ("modules.host_header", "HostHeaderModule"),
            "mass_assignment": ("modules.mass_assignment", "MassAssignmentModule"),
            "webdav": ("modules.webdav", "WebDAVModule"),
            "ssi_injection": ("modules.ssi_injection", "SSIInjectionModule"),
            # APIs
            "soap_wsdl": ("modules.soap_wsdl", "SOAPModule"),
            "grpc": ("modules.grpc", "GRPCModule"),
            "webhook_ssrf": ("modules.webhook_ssrf", "WebhookSSRFModule"),
            # Cloud & Container
            "container_escape": ("modules.container_escape", "ContainerEscapeModule"),
            "cicd_injection": ("modules.cicd_injection", "CICDInjectionModule"),
            "aws_iam_privesc": ("modules.aws_iam_privesc", "AWSIAMPrivescModule"),
            "service_mesh": ("modules.service_mesh", "ServiceMeshModule"),
            # IoT/OT/ICS
            "ics_protocols": ("modules.ics_protocols", "ICSProtocolModule"),
            # Supply Chain
            "typosquatting": ("modules.typosquatting", "TyposquattingModule"),
            # Cryptography
            "covert_channels": ("modules.covert_channels", "CovertChannelModule"),
            "crypto_weakness": ("modules.crypto_weakness", "CryptoWeaknessModule"),
            # Post-Exploitation
            "credential_dump": ("modules.credential_dump", "CredentialDumpModule"),
            "lateral_movement": ("modules.lateral_movement", "LateralMovementModule"),
            "ad_attacks": ("modules.ad_attacks", "ADAttackModule"),
            # Zero-Day
            "coverage_fuzz": ("modules.coverage_fuzz", "CoverageFuzzModule"),
            "symbolic_exec": ("modules.symbolic_exec", "SymbolicExecModule"),
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

    def _set_phase(self, phase, *, payload: Optional[dict] = None):
        """Advance the canonical pipeline state machine to *phase*.

        Updates the granular ``self.pipeline['phase']`` (one of the 21
        canonical names from :class:`Phase`), keeps the legacy 4-string
        partition tracker in sync, and emits a ``phase_advance`` event
        to the dashboard.  When the state machine is unavailable
        (very old import path), this falls back to writing the phase
        string directly so old behaviour is preserved.
        """
        if self._state_machine is None or self._phase_enum is None:
            # Fallback: best-effort assignment when the contract module
            # failed to import.  This keeps the engine usable on
            # severely broken installs at the cost of granular tracking.
            self.pipeline["phase"] = getattr(phase, "value", str(phase))
            self.emit_pipeline_event(
                "phase_advance",
                {"phase": self.pipeline["phase"], **(payload or {})},
            )
            return

        # Advance the state machine.  ``advance_to`` validates that the
        # transition is forward-only; in non-strict mode invalid jumps
        # silently no-op, which is what we want when callers re-enter
        # an optional phase (e.g. report runner re-runs exploit_search
        # on demand for the attack map).
        try:
            self._state_machine.advance_to(phase)
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("PipelineStateMachine.advance_to(%s) failed: %s", phase, exc)

        current = self._state_machine.current
        partition = self._phase_partition.get(current)
        self.pipeline["phase"] = current.value
        if partition is not None:
            self.pipeline["partition"] = partition.value

        self.emit_pipeline_event(
            "phase_advance",
            {
                "phase": current.value,
                "partition": partition.value if partition else None,
                **(payload or {}),
            },
        )

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

    def add_finding_dict(self, finding_dict: dict):
        """Add a raw finding dict to self.findings (used by browser scanner and plugins).

        Converts the dict to a CanonicalFinding if possible, otherwise stores as-is.
        """
        try:
            from core.models import CanonicalFinding
            f = CanonicalFinding(
                technique=finding_dict.get("technique", "Unknown"),
                url=finding_dict.get("url", ""),
                method=finding_dict.get("method", "GET"),
                param=finding_dict.get("param", ""),
                payload=finding_dict.get("payload", ""),
                severity=finding_dict.get("severity", "INFO"),
                confidence=float(finding_dict.get("confidence", 0.5)),
                cvss=float(finding_dict.get("cvss", 0.0)),
            )
            with self._findings_lock:
                self.findings.append(f)
        except Exception:
            # Fallback: store the raw dict
            with self._findings_lock:
                self.findings.append(finding_dict)


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
        """Run integrated external tools automatically when enabled and convert
        their results into canonical findings so the framework actually uses them
        in jobs, tasks, reports, and attack planning.

        Tools run: whatweb, httpx, nikto, nuclei, nmap, plus recon arsenal
        (subfinder, amass, katana, etc) when available. Results are turned
        into Findings.
        """
        if not self.config.get("auto_external_tools", False):
            return
        if not self.tools:
            return

        from urllib.parse import urlparse

        domain = urlparse(target).hostname or ""
        all_results = {}

        # OBSERVABILITY (SEC-011): external-tool failures are scan-
        # completeness events, not verbose-only noise.  They are classified
        # and logged structurally so a missing tool phase is diagnosable
        # after the fact instead of vanishing silently.
        try:
            all_results.update(self.tools.run_recon_suite(target, domain=domain))
        except Exception as exc:
            logger.warning(
                "external_tools failure",
                extra={"phase": "recon_suite", "target": target, "classification": "recoverable", "error": str(exc)},
            )
            if self.config.get("verbose"):
                print(f"{Colors.warning(f'External recon suite error: {exc}')}")

        try:
            all_results.update(self.tools.run_vuln_scan(target))
        except Exception as exc:
            logger.warning(
                "external_tools failure",
                extra={"phase": "vuln_scan", "target": target, "classification": "recoverable", "error": str(exc)},
            )
            if self.config.get("verbose"):
                print(f"{Colors.warning(f'External vuln suite error: {exc}')}")

        # Also run full recon arsenal if available (subdomain, crawler, etc)
        if getattr(self, "recon_arsenal", None):
            try:
                arsenal_results = self.recon_arsenal.run_full_recon(target, domain=domain)
                all_results.update(arsenal_results)
            except Exception as exc:
                logger.warning(
                    "external_tools failure",
                    extra={"phase": "recon_arsenal", "target": target, "classification": "recoverable", "error": str(exc)},
                )
                if self.config.get("verbose"):
                    print(f"{Colors.warning(f'Recon arsenal error: {exc}')}")

        if all_results:
            # SECURITY FIX (SEC-013, defense in depth): simulation stub
            # output must never become findings, even when simulation mode
            # is enabled — fabricated data is for workflow demos only.
            try:
                from core.tool_runtime import is_simulated_tool as _is_sim_tool
            except Exception:
                def _is_sim_tool(_name):
                    return False

            # Convert tool findings into engine findings so framework uses them
            converted = 0
            skipped_simulated = []
            for tool_name, res in all_results.items():
                if not getattr(res, "success", False):
                    continue
                if _is_sim_tool(tool_name):
                    skipped_simulated.append(tool_name)
                    continue
                for f in getattr(res, "findings", []) or []:
                    try:
                        # Normalize tool finding dict to engine Finding
                        if isinstance(f, dict):
                            technique = f.get("type") or f.get("template_id") or f.get("technology") or f.get("subdomain") or tool_name
                            # Build meaningful technique label
                            if tool_name == "nuclei" and f.get("name"):
                                technique = f"External Tool (Nuclei: {f.get('name')})"
                            elif tool_name == "nmap" and f.get("type") == "open_port":
                                technique = f"External Tool (Nmap: Open Port {f.get('port')}/{f.get('protocol')})"
                            elif tool_name in ("subfinder", "amass") and f.get("subdomain"):
                                technique = f"External Tool ({tool_name}: Subdomain {f.get('subdomain')})"
                            elif f.get("url"):
                                technique = f"External Tool ({tool_name}: {f.get('url')[:60]})"
                            else:
                                technique = f"External Tool ({tool_name}: {technique})"

                            evidence = f.get("details") or f.get("msg") or f.get("description") or str(f)[:500]
                            url = f.get("url") or f.get("host") or f.get("matched_at") or target

                            # Severity mapping
                            sev = "INFO"
                            if tool_name == "nuclei":
                                raw_sev = (f.get("severity") or "").upper()
                                if raw_sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                                    sev = raw_sev
                            elif tool_name == "nmap" and f.get("type") == "vulnerability":
                                sev = "HIGH"
                            elif tool_name in ("nikto",):
                                sev = "MEDIUM"

                            finding = Finding(
                                technique=technique,
                                url=url,
                                severity=sev,
                                confidence=0.85 if tool_name in ("nuclei", "nmap") else 0.70,
                                evidence=evidence[:500],
                                extracted_data=str(f)[:1000],
                            )
                            self.add_finding(finding)
                            converted += 1
                    except Exception:
                        continue

            results = [res for res in all_results.values() if hasattr(res, "success")]
            if skipped_simulated:
                logger.info(
                    "External tools: skipped findings conversion for simulated tools: %s",
                    ", ".join(sorted(skipped_simulated)),
                )
            self.emit_pipeline_event(
                "external_tools_completed",
                {
                    "tools": list(all_results.keys()),
                    "success_count": sum(1 for r in results if r.success),
                    "failure_count": sum(1 for r in results if not r.success),
                    "findings_converted": converted,
                    "simulated_skipped": sorted(skipped_simulated),
                },
            )
            if self.config.get("verbose"):
                print(f"{Colors.info(f'External tools: {converted} findings converted from {len(all_results)} tools')}")

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
            # Audit-trail --unsafe-mode at scan start: the flag is the
            # operator's explicit acknowledgement that report-flood,
            # severity-floor, structural-dedup, and FP-floor caps are
            # lifted for this run only. Scope/auth gates unchanged.
            if self.config.get("unsafe_mode"):
                self.audit.log_config(
                    "scan.unsafe_mode",
                    result="enabled",
                    scan_id=self.scan_id,
                    target=target,
                    severity_floor=self.config.get("attack_severity_floor", "LOW"),
                    per_type_cap="lifted",
                    structural_dedup="skipped",
                    fp_confidence_floor="disabled",
                    attack_exploit_ceiling="lifted",
                    attack_confidence_threshold="lifted",
                )
        if self.notifications:
            self.notifications.notify_scan_started(self.scan_id, target)

        print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
        print(f"{Colors.CYAN}  Scanning: {target}{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*60}{Colors.RESET}\n")

        # ── PIPELINE: Phase 1 - Recon & Scan ─────────────────────────
        # Drive the canonical state machine to SCOPE (the first phase
        # scan() actually runs after init); this updates pipeline['phase']
        # to a granular value and pipeline['partition'] to "recon" via
        # the partition map. The legacy 4-bucket status tracker
        # (pipeline['recon']['status']) is kept in sync separately.
        self._set_phase(Phase.SCOPE, payload={"target": target})
        self.pipeline["recon"]["status"] = "running"
        self.emit_pipeline_event("phase_start", {"phase": "recon", "target": target})

        # ── §1. SCOPE & POLICY ENGINE (Phase 3 of 21) ─────────────────
        self.scope.set_target_scope(target)
        self.scope.load_robots_txt(target)

        # Test connection
        if not self.requester.test_connection(target):
            print(f"{Colors.error(f'Cannot connect to {target}')}")
            # Mark scan as complete so generate_reports() doesn't see
            # a half-initialized engine. Without this, end_time stays
            # ``None`` and the LLM scan-summary / HTML reporter format
            # ``None`` or ``0`` for duration on every unreachable target.
            self.end_time = datetime.now(timezone.utc)
            self.pipeline["recon"]["status"] = "failed"
            self.emit_pipeline_event(
                "phase_end",
                {"phase": "recon", "reason": "target_unreachable", "target": target},
            )
            try:
                self._set_phase(Phase.DONE, payload={"reason": "target_unreachable"})
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug("Could not advance to DONE phase on early exit: %s", exc)
            if self.audit:
                self.audit.log_scan(
                    "scan.unreachable",
                    target=target,
                    details={"scan_id": self.scan_id},
                )
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

        # ── PHASE 4 of 21: SHIELD DETECT (CDN + WAF) ─────────────────
        shield_profile = None
        if modules_config.get("shield_detect", False):
            self._set_phase(Phase.SHIELD_DETECT)
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

        # ── PHASE 5 of 21: REAL_IP discovery ─────────────────────────
        real_ip_result = None
        if modules_config.get("real_ip", False):
            needs_discovery = True
            if shield_profile:
                needs_discovery = shield_profile.get("needs_origin_discovery", False)
            if needs_discovery:
                self._set_phase(Phase.REAL_IP)
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

        # ── PHASE 6 of 21: PASSIVE_RECON & DISCOVERY (fan-out) ──────
        # This replaces the individual recon/port/crawl/discovery calls
        # with a unified fan-out that merges all URL sources.
        fanout_result = None
        if modules_config.get("passive_recon", False):
            self._set_phase(Phase.PASSIVE_RECON)
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
            # ── §2. DISCOVERY & GRAPH ENGINE (Phase 7 of 21) ─────────
            self._set_phase(Phase.DISCOVERY)
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

            # ── Build canonical TargetSurface from crawler artifacts ──
            # Runs after scope filtering so the surface only contains
            # in-scope endpoints.  Errors are non-fatal.
            try:
                robots_text = getattr(getattr(self, "scope", None), "_robots_text", "") or ""
                self.build_surface(effective_target, crawler=crawler, robots_text=robots_text)
            except Exception as _surf_exc:
                logger.debug("TargetSurface build skipped: %s", _surf_exc)

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

        # ── §3. INPUT EXTRACTION (Phase 8 of 21) ─────────────────────
        self._set_phase(Phase.INPUT_EXTRACTION)
        # ── §4. CONTEXT INTELLIGENCE (Phase 9 of 21) ─────────────────
        self._set_phase(Phase.CONTEXT_INTEL)
        enriched_params = self.context.analyze_parameters(parameters)

        # ── PHASE 10 of 21: INTELLIGENCE ENRICHMENT ──────────────────
        intel_bundle = None
        if modules_config.get("enrich", False):
            self._set_phase(Phase.ENRICHMENT)
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

        # ── PHASE 11 of 21: ATTACK SURFACE PRIORITIZATION ────────────
        scan_queue = None
        if modules_config.get("enrich", False) and intel_bundle:
            self._set_phase(Phase.PRIORITIZATION)
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
        # Granular phase advance is driven by the BASELINE block below;
        # here we only flip the legacy 4-bucket scan tracker on so the
        # dashboard's partition card lights up.
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

        # ── §6. BASELINE ENGINE (Phase 12 of 21) ─────────────────────
        self._set_phase(Phase.BASELINE)
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

        # ── §7. ADAPTIVE TESTING (Phase 13 of 21, AI-driven module sel.) ──
        self._set_phase(Phase.ADAPTIVE_TESTING)
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
        # the response body. We honour the per-module declaration on
        # ``BaseModule.requires_reflection`` so that new modules can opt
        # into the gate without editing the engine.  XSS and SSTI are
        # included as a baseline for backward compatibility.
        REFLECTION_DEPENDENT_MODULES = {
            mkey
            for mkey, minst in self._modules.items()
            if getattr(minst, "requires_reflection", False)
        }
        REFLECTION_DEPENDENT_MODULES.update({"xss", "ssti"})
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
                    # Rate limiting is handled by the Requester via
                    # attach_rate_limiter() — no need to call it here
                    # (which caused double-throttling and halved throughput).
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

        # ── PHASE 14 of 21: SCAN_WORKERS (vulnerability workers A-E) ─
        # If Phase 7 produced a scan queue, run it through the worker pool
        if scan_queue:
            self._set_phase(Phase.SCAN_WORKERS)
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

        # ── PHASE 15 of 21: VERIFICATION (post-worker) ──────────────
        verification_result = None
        if modules_config.get("chain_detect", False) and self.findings:
            self._set_phase(Phase.VERIFICATION)
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

        # ── PHASE 16 of 21: EXPLOIT_SEARCH (7-source reference search) ─
        if modules_config.get("exploit_search", False) and self.findings:
            self._set_phase(Phase.EXPLOIT_SEARCH)
            try:
                from core.exploit_searcher import ExploitSearcher

                exploit_searcher = ExploitSearcher(self)
                self.findings = exploit_searcher.run(self.findings)
            except Exception as e:
                if self.config.get("verbose"):
                    print(f"{Colors.error(f'Phase 9B exploit search error: {e}')}")

        # ── PHASE 17 of 21: AGENT_SCAN (autonomous goal-driven OODA) ─
        agent_result = None
        if modules_config.get("agent_scan", False):
            self._set_phase(Phase.AGENT_SCAN)
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

        # ── PHASE 18 of 21: EXPLOIT (Attack Router / legacy paths) ───
        # Route confirmed vulns to the right exploitation tool.
        # Granular phase EXPLOIT is set here; the legacy 4-bucket
        # tracker for the exploit partition flips on at the same time
        # for backward-compatible dashboards.
        self._set_phase(Phase.EXPLOIT, payload={"findings_to_route": len(self.findings)})
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
        # Auto-attack runs ONLY when explicitly opted-in via --auto-exploit
        # or --smart-attack AND --authorized is set.
        exploitable_findings = [f for f in self.findings if f.severity in ("CRITICAL", "HIGH") and f.confidence >= 0.6]
        should_auto_attack = modules_config.get("auto_exploit", False) or (
            exploitable_findings and modules_config.get("smart_attack", False)
        )
        if should_auto_attack and self.findings:
            # Authorization gate: require --authorized or ATOMIC_AUTHORIZED=1
            # for ALL post-exploit actions. Fail-closed.
            if not self.config.get("_authorized") and not self.config.get("authorized"):
                if self.config.get("verbose"):
                    print(f"{Colors.warning('Auto-attack blocked: --authorized required for exploitation.')}")
                should_auto_attack = False
            else:
                try:
                    from core.authorization import require_authorized
                    require_authorized("auto-attack", target=target)
                except (ImportError, PermissionError) as _auth_exc:
                    if self.config.get("verbose"):
                        print(f"{Colors.warning(f'Auto-attack blocked: {_auth_exc}')}")
                    should_auto_attack = False

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

        # Legacy manual flags kept for backward compatibility.
        # NOTE: ShellUploader(scan_only=True) is the default (used during
        # the scan phase for vulnerability *detection* via test_url()).
        # Here in the exploit phase we explicitly pass scan_only=False
        # so that run() actually deploys webshells.  Without this flag
        # run() short-circuits at its scan_only guard and silently does
        # nothing — the bug noted in LOGIC_MAP.md "Known Drift #3".
        _is_authorized = self.config.get("_authorized") or self.config.get("authorized")

        if modules_config.get("shell", False) and self.findings:
            if not _is_authorized:
                if self.config.get("verbose"):
                    print(f"{Colors.warning('Shell upload skipped: --authorized required.')}")
            else:
                try:
                    from modules.uploader import ShellUploader
                    uploader = ShellUploader(self, scan_only=False)
                    uploader.run(self.findings, forms)
                except Exception as e:
                    if self.config.get("verbose"):
                        print(f"{Colors.error(f'Shell upload error: {e}')}")

        if modules_config.get("dump", False) and self.findings:
            if not _is_authorized:
                if self.config.get("verbose"):
                    print(f"{Colors.warning('Data dump skipped: --authorized required.')}")
            else:
                try:
                    from modules.dumper import DataDumper
                    dumper = DataDumper(self)
                    dumper.run(self.findings)
                except Exception as e:
                    if self.config.get("verbose"):
                        print(f"{Colors.error(f'Data dump error: {e}')}")

        if modules_config.get("os_shell", False) and self.findings:
            if not _is_authorized:
                if self.config.get("verbose"):
                    print(f"{Colors.warning('OS shell skipped: --authorized required.')}")
            else:
                try:
                    from core.os_shell import OSShellHandler
                    handler = OSShellHandler(self)
                    handler.run(self.findings, forms)
                except Exception as e:
                    if self.config.get("verbose"):
                        print(f"{Colors.error(f'OS shell error: {e}')}")

        if modules_config.get("brute", False):
            if not _is_authorized:
                if self.config.get("verbose"):
                    print(f"{Colors.warning('Brute force skipped: --authorized required.')}")
            else:
                try:
                    from modules.brute_force import BruteForceModule
                    bruter = BruteForceModule(self)
                    bruter.run(forms)
                except Exception as e:
                    if self.config.get("verbose"):
                        print(f"{Colors.error(f'Brute force error: {e}')}")

        if modules_config.get("exploit_chain", False) and self.findings:
            if not _is_authorized:
                if self.config.get("verbose"):
                    print(f"{Colors.warning('Exploit chain skipped: --authorized required.')}")
            else:
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
        # Granular phase REPORT is set here; PHASE 19 of 21.
        self._set_phase(Phase.REPORT)
        self.pipeline["collect"]["status"] = "running"
        self.emit_pipeline_event("phase_start", {"phase": "collect"})

        self.end_time = datetime.now(timezone.utc)

        # ── Clear persistence progress on complete scan ───────────────
        self.persistence.clear_progress()

        # ── PHASE 19 of 21: REPORT (commit + render reports) ─────────
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

        # ── PHASE 20 of 21: ATTACK_MAP (exploit-aware graph) ─────────
        attack_map_result = None
        if modules_config.get("attack_map", False) and self.findings:
            self._set_phase(Phase.ATTACK_MAP)
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
        # Phase 21 of 21: terminal DONE state.
        self._set_phase(Phase.DONE)
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

        # Skip duplicate findings.
        # The dedup key intentionally includes a payload fingerprint so
        # that distinct techniques against the same (url, param) — e.g.
        # error-based vs. boolean vs. time-based SQLi — remain separate
        # records during triage. Pure (technique,url,param) collapsed
        # them into one and lost evidence.
        import hashlib

        def _payload_fingerprint(value: str) -> str:
            if not value:
                return ""
            return hashlib.sha1(value.encode("utf-8", "replace"), usedforsecurity=False).hexdigest()[:8]

        new_key = (
            finding.technique,
            finding.url,
            finding.param,
            _payload_fingerprint(finding.payload or ""),
        )

        # Critical section: dedup-check and append must be atomic when
        # ``add_finding`` is called from multiple worker threads (see
        # :mod:`core.scan_worker_pool`).  Without this lock the dedup
        # loop can race with appends from sibling threads, producing
        # duplicate or lost findings.
        with self._findings_lock:
            for existing in self.findings:
                existing_key = (
                    existing.technique,
                    existing.url,
                    existing.param,
                    _payload_fingerprint(existing.payload or ""),
                )
                if existing_key == new_key:
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

        # ── Streaming auto-exploitation ───────────────────────────
        # If the FullAttacker is installed (--full-attack / --smart-
        # attack with --authorized), give it a chance to chain into
        # post-exploitation immediately. Do this AFTER persisting the
        # finding so the exploit attempt and its results land in the
        # same scan record. Failures here must not block the scan.
        if self.full_attacker is not None and finding.severity in ("CRITICAL", "HIGH"):
            try:
                rec = self.full_attacker.maybe_attack(finding)
                if rec is not None:
                    self.emit_pipeline_event(
                        "auto_exploit_streamed",
                        {
                            "family": rec.family,
                            "url": rec.url,
                            "param": rec.param,
                            "actions": rec.actions_attempted,
                            "success": rec.success,
                        },
                    )
            except Exception as exc:
                logger.debug("FullAttacker.maybe_attack failed: %s", exc)

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

    def build_surface(
        self,
        target: str,
        *,
        crawler=None,
        robots_text: str = "",
        sitemap_text: str = "",
        openapi_spec: dict = None,
        js_texts: list = None,
        responses: list = None,
    ):
        """Build (or rebuild) the canonical ``TargetSurface`` for this scan.

        Stores the result as ``self.surface`` and emits a pipeline event
        so the web dashboard can report the number of discovered endpoints.

        This is called automatically from ``scan()`` after crawling completes,
        but can also be called from tests or runners directly.

        Returns the built ``TargetSurface``.
        """
        from core.surface import build_target_surface
        from core.models import ScanConfig

        scan_config = ScanConfig.from_raw(self.config)
        scan_config.target = target

        self.surface = build_target_surface(
            scan_config,
            target,
            crawler=crawler,
            robots_text=robots_text,
            sitemap_text=sitemap_text,
            openapi_spec=openapi_spec,
            js_texts=js_texts,
            responses=responses,
        )

        self.emit_pipeline_event(
            "surface_built",
            {
                "surface_id": self.surface.surface_id,
                "endpoint_count": len(self.surface.endpoints),
                "target": target,
            },
        )
        return self.surface

    def get_canonical_findings(self) -> list:
        """Return all ``CanonicalFinding`` objects registered via ``core.emit``.

        These are richer than the legacy ``self.findings`` list and include
        full evidence, repro, and verification metadata.
        """
        return list(self._canonical_findings.values())

    def get_coverage_summary(self):
        """Compute a :class:`core.models.CoverageSummary` for this scan.

        Read-only aggregation over data the engine already holds: the
        discovered ``TargetSurface`` (endpoints), the enabled modules
        (validators), and the canonical findings (validated cells). Returns
        ``None`` if nothing is available to summarize.

        This threads no state through the scan loop — it is safe to call at
        any time after a scan and is consumed by reporters and the web API.
        """
        from core.coverage import build_coverage

        findings = self.get_canonical_findings()
        if self.surface is None and not findings:
            return None
        validators = [
            name for name, enabled in (self.config.get("modules", {}) or {}).items()
            if enabled is True
        ]
        engine = build_coverage(self.surface, findings, validators=validators or None)
        return engine.summary()

    def get_surface_ledger(self):
        """Build a :class:`core.surface_ledger.SurfaceLedger` for this scan.

        Read-only aggregation: enabled modules mark their attack-surface
        category as tested; canonical findings mark their category as having
        issues. Surfaces no enabled module covers stay NOT_TESTED and are
        reported as explicit blind spots. Threads no state through the scan
        loop.
        """
        from core.surface_map import build_surface_ledger

        enabled = [
            name for name, on in (self.config.get("modules", {}) or {}).items()
            if on is True
        ]
        return build_surface_ledger(enabled, self.get_canonical_findings())

    def get_coverage_plan(self):
        """Compute a coverage-closure plan for this scan ("leave no blind spot").

        Combines the per-endpoint coverage grid with the per-category surface
        ledger to list what has not been tested and a prioritized set of
        recommended safe validations. Returns ``None`` if there is nothing to
        plan over. Read-only; recommends but never executes.
        """
        from core.coverage import build_coverage
        from core.coverage_planner import plan_coverage_gaps

        findings = self.get_canonical_findings()
        if self.surface is None and not findings:
            return None
        validators = [
            name for name, on in (self.config.get("modules", {}) or {}).items()
            if on is True
        ]
        cov = build_coverage(self.surface, findings, validators=validators or None)
        return plan_coverage_gaps(cov, self.get_surface_ledger(), validators or None)

    def run_coverage_closure(self, auto_validators=None, budget=100, max_iterations=25):
        """Actively drive real non-invasive validation to coverage closure.

        Runs the enabled, non-invasive validator modules against the discovered
        surface until gaps close or the budget is spent, then returns the
        driver's run report. Invasive/exploitative validators are never
        auto-run (they are reported as ``skipped_invasive``); exploitation
        stays behind the authorization gate.

        This performs real requests and is an explicit, opt-in operation — it
        is NOT part of the default scan flow.
        """
        from core.coverage_executor import run_coverage_closure

        return run_coverage_closure(
            self, auto_validators=auto_validators,
            budget=budget, max_iterations=max_iterations,
        )

    def get_authz_matrix(self):
        """Build a :class:`core.authz_matrix.AuthorizationMatrix` from this
        scan's access-control findings (IDOR/BOLA), read-only. Returns the
        matrix (possibly empty)."""
        from core.authz_matrix import build_authz_matrix_from_findings

        return build_authz_matrix_from_findings(self.get_canonical_findings())

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
