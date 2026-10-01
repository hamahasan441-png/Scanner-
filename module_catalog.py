"""Single registry of engine attack modules.

``main.py``, ``core/cli``, the ``atomic`` profiles, and the web full scan
all read this list. Do not copy it.

Tiers
-----
detect, probe
    Web checks. A profile may turn them on by itself.
exploit
    Internal-network and post-exploitation modules. Auto-enabled only by
    ``--point-to-point`` and the atomic ``full`` profile (that profile
    already requires ``--authorized``). A plain ``--full`` web scan does
    not turn them on. An explicit flag still does.
"""
from __future__ import annotations

from dataclasses import dataclass


# Profile / CLI modes that may auto-enable a module.
QUICK = frozenset({"quick", "standard", "deep", "cli_full", "atomic_full", "point_to_point"})
FROM_STANDARD = frozenset({"standard", "deep", "cli_full", "atomic_full", "point_to_point"})
FROM_DEEP = frozenset({"deep", "cli_full", "atomic_full", "point_to_point"})
FROM_FULL = frozenset({"cli_full", "atomic_full", "point_to_point"})
EXPLOIT = frozenset({"atomic_full", "point_to_point"})


@dataclass(frozen=True)
class ModuleSpec:
    key: str
    module: str
    class_name: str
    tier: str
    modes: frozenset
    flag: str
    dest: str
    aliases: tuple
    help: str
    web_full: bool = False


def _spec(key, module, class_name, tier, modes, help, *, web_full=False, dest=None, flag=None, aliases=()):
    return ModuleSpec(
        key=key,
        module=module,
        class_name=class_name,
        tier=tier,
        modes=modes,
        flag=flag or ("--" + key.replace("_", "-")),
        dest=dest or key,
        aliases=tuple(aliases),
        help=help,
        web_full=web_full,
    )


# (key, module, class, tier, modes, help, web_full)
_ROWS = [
    ("sqli", "modules.sqli", "SQLiModule", "detect", QUICK, "SQL injection", True),
    ("xss", "modules.xss", "XSSModule", "detect", QUICK, "Cross-site scripting", True),
    ("lfi", "modules.lfi", "LFIModule", "detect", QUICK, "Local and remote file inclusion", True),
    ("cmdi", "modules.cmdi", "CommandInjectionModule", "detect", QUICK, "Command injection", True),
    ("ssrf", "modules.ssrf", "SSRFModule", "detect", QUICK, "Server-side request forgery", True),
    ("ssti", "modules.ssti", "SSTIModule", "detect", FROM_STANDARD, "Server-side template injection", True),
    ("xxe", "modules.xxe", "XXEModule", "detect", FROM_STANDARD, "XML external entity injection", True),
    ("idor", "modules.idor", "IDORModule", "detect", FROM_STANDARD, "Insecure direct object reference", True),
    ("nosql", "modules.nosqli", "NoSQLModule", "detect", FROM_STANDARD, "NoSQL injection", True),
    ("cors", "modules.cors", "CORSModule", "detect", FROM_STANDARD, "CORS misconfiguration", True),
    ("jwt", "modules.jwt", "JWTModule", "detect", FROM_STANDARD, "JWT weaknesses", True),
    ("open_redirect", "modules.open_redirect", "OpenRedirectModule", "detect", FROM_STANDARD, "Open redirect", False),
    ("crlf", "modules.crlf", "CRLFModule", "detect", FROM_STANDARD, "CRLF injection", False),
    ("hpp", "modules.hpp", "HPPModule", "detect", FROM_STANDARD, "HTTP parameter pollution", False),
    ("graphql", "modules.graphql", "GraphQLModule", "probe", FROM_DEEP, "GraphQL attacks", False),
    ("proto_pollution", "modules.proto_pollution", "ProtoPollutionModule", "probe", FROM_DEEP, "Prototype pollution", False),
    ("upload", "modules.uploader", "ShellUploader", "probe", FROM_DEEP, "File upload checks", True),
    ("race_condition", "modules.race_condition", "RaceConditionModule", "probe", FROM_DEEP, "Race conditions", False),
    ("websocket", "modules.websocket", "WebSocketModule", "probe", FROM_DEEP, "WebSocket attacks", False),
    ("deserialization", "modules.deserialization", "DeserializationModule", "probe", FROM_DEEP, "Insecure deserialization", False),
    ("osint", "modules.osint", "OSINTModule", "probe", FROM_DEEP, "OSINT reconnaissance", False),
    ("fuzzer", "modules.fuzzer", "FuzzerModule", "probe", FROM_DEEP, "Parameter and header fuzzing", False),
    ("cloud_scan", "modules.cloud_scanner", "CloudScannerModule", "probe", FROM_DEEP, "Cloud metadata and bucket checks", False),
    ("h2_smuggling", "modules.h2_smuggling", "H2SmugglingModule", "probe", FROM_DEEP, "HTTP/2 request smuggling", False),
    ("cache_poisoning", "modules.cache_poisoning", "CachePoisoningModule", "probe", FROM_DEEP, "Web cache poisoning", False),
    ("api_abuse", "modules.api_abuse", "APIAbuseModule", "probe", FROM_DEEP, "API abuse and rate-limit bypass", False),
    ("deep_scan", "modules.deep_scan", "DeepScanModule", "probe", FROM_DEEP, "Deep multi-technique scan", False),
    ("gatebreaker", "modules.gatebreaker", "GateBreakerModule", "probe", FROM_DEEP, "WAF, auth, and rate-limit gate bypass", True),
    ("firewall_bypass", "modules.firewall_bypass", "FirewallBypassModule", "probe", FROM_DEEP, "Network firewall and ACL bypass", True),
    ("tls", "modules.tls_scan", "TLSScanModule", "probe", FROM_DEEP, "TLS and crypto configuration", True),
    ("secrets", "modules.secrets_scan", "SecretsScanModule", "probe", FROM_DEEP, "Exposed secrets in responses", True),
    ("session_cookie", "modules.session_cookie", "SessionCookieModule", "probe", FROM_DEEP, "Session cookie hygiene", True),
    ("openapi_ghost", "modules.openapi_ghost", "OpenAPIGhostModule", "probe", FROM_DEEP, "Unlinked OpenAPI paths", True),
    ("ai_app_probe", "modules.ai_app_probe", "AIAppProbeModule", "probe", FROM_DEEP, "LLM prompt-injection checks", True),
    ("saml_webauthn", "modules.saml_webauthn", "SAMLWebAuthnModule", "probe", FROM_DEEP, "SAML and WebAuthn fingerprint", True),
    ("waf", "modules.waf", "WAFBypass", "probe", FROM_DEEP, "WAF fingerprint and payload-family bypass", True),
    ("oauth", "modules.oauth", "OAuthModule", "probe", FROM_FULL, "OAuth and OIDC checks", False),
    ("mfa_bypass", "modules.mfa_bypass", "MFABypassModule", "probe", FROM_FULL, "MFA bypass checks", False),
    ("api_versioning", "modules.api_versioning", "APIVersioningModule", "probe", FROM_FULL, "Deprecated API versions", False),
    ("dep_confusion", "modules.dep_confusion", "DependencyConfusionModule", "probe", FROM_FULL, "Dependency confusion surface", False),
    ("llm_logic", "modules.llm_logic", "LLMLogicModule", "probe", FROM_FULL, "LLM business-logic flaws", False),
    ("advanced_weapon", "modules.advanced_weapon", "AdvancedWeaponModule", "probe", FROM_FULL, "Chained SSRF, JWT, GraphQL, and prototype-pollution techniques", False),
    ("exotic_bypass", "modules.exotic_bypass", "ExoticBypassModule", "probe", FROM_FULL, "Parser, cache, and path-quirk bypasses", False),
    ("parse_split_bypass", "modules.parse_split_bypass", "ParseSplitBypassModule", "probe", FROM_FULL, "Parser-discrepancy bypasses", False),
    ("request_smuggling", "modules.request_smuggling", "RequestSmugglingModule", "probe", FROM_FULL, "HTTP/1.1 request smuggling", False),
    ("k8s_control_plane", "modules.k8s_control_plane", "K8sControlPlaneModule", "probe", FROM_FULL, "Kubernetes control-plane exposure", False),
    ("azure_entra", "modules.azure_entra", "AzureEntraModule", "probe", FROM_FULL, "Azure Entra tenant fingerprint", False),
    ("gh_actions_oidc", "modules.gh_actions_oidc", "GHActionsOIDCModule", "probe", FROM_FULL, "Public GitHub Actions OIDC misconfig", False),
    ("mobile_static", "modules.mobile_static", "MobileStaticModule", "probe", FROM_FULL, "Static APK and IPA analysis", False),
    ("csrf", "modules.csrf", "CSRFModule", "probe", FROM_FULL, "Cross-site request forgery", False),
    ("clickjacking", "modules.clickjacking", "ClickjackingModule", "probe", FROM_FULL, "Clickjacking", False),
    ("host_header", "modules.host_header", "HostHeaderModule", "probe", FROM_FULL, "Host header attacks", False),
    ("mass_assignment", "modules.mass_assignment", "MassAssignmentModule", "probe", FROM_FULL, "Mass assignment", False),
    ("webdav", "modules.webdav", "WebDAVModule", "probe", FROM_FULL, "WebDAV exposure", False),
    ("ssi_injection", "modules.ssi_injection", "SSIInjectionModule", "probe", FROM_FULL, "Server-side include injection", False),
    ("soap_wsdl", "modules.soap_wsdl", "SOAPModule", "probe", FROM_FULL, "SOAP and WSDL checks", False),
    ("grpc", "modules.grpc", "GRPCModule", "probe", FROM_FULL, "gRPC checks", False),
    ("webhook_ssrf", "modules.webhook_ssrf", "WebhookSSRFModule", "probe", FROM_FULL, "Webhook SSRF", False),
    ("service_mesh", "modules.service_mesh", "ServiceMeshModule", "probe", FROM_FULL, "Service mesh exposure", False),
    ("typosquatting", "modules.typosquatting", "TyposquattingModule", "probe", FROM_FULL, "Dependency typosquatting", False),
    ("crypto_weakness", "modules.crypto_weakness", "CryptoWeaknessModule", "probe", FROM_FULL, "Weak cryptography", False),
    ("cloud_deep", "modules.cloud_deep", "CloudDeepModule", "exploit", EXPLOIT, "Confirm leaked cloud credentials against live APIs", False),
    ("cve_confirm", "modules.cve_confirm", "CVEConfirmModule", "exploit", EXPLOIT, "Confirm CVEs with a sandboxed template", False),
    ("nhi_audit", "modules.nhi_audit", "NHIAuditModule", "exploit", EXPLOIT, "Non-human identity permission audit", False),
    ("internal_segment", "modules.internal_segment_map", "InternalSegmentMapModule", "exploit", EXPLOIT, "Map internal ports from confirmed SSRF evidence", False),
    ("adcs_esc", "modules.adcs_esc", "ADCSDiscoveryModule", "exploit", EXPLOIT, "ADCS web-enrollment discovery", False),
    ("dns_attacks", "modules.dns_attacks", "DNSAttackModule", "exploit", EXPLOIT, "DNS attacks", False),
    ("snmp_enum", "modules.snmp_enum", "SNMPEnumModule", "exploit", EXPLOIT, "SNMP enumeration", False),
    ("smb_attacks", "modules.smb_attacks", "SMBAttackModule", "exploit", EXPLOIT, "SMB attacks", False),
    ("ssh_attacks", "modules.ssh_attacks", "SSHAttackModule", "exploit", EXPLOIT, "SSH attacks", False),
    ("rdp_attacks", "modules.rdp_attacks", "RDPAttackModule", "exploit", EXPLOIT, "RDP attacks", False),
    ("nfs_enum", "modules.nfs_enum", "NFSEnumModule", "exploit", EXPLOIT, "NFS enumeration", False),
    ("rpc_enum", "modules.rpc_enum", "RPCEnumModule", "exploit", EXPLOIT, "RPC enumeration", False),
    ("vnc_attacks", "modules.vnc_attacks", "VNCAttackModule", "exploit", EXPLOIT, "VNC attacks", False),
    ("ipv6_attacks", "modules.ipv6_attacks", "IPv6AttackModule", "exploit", EXPLOIT, "IPv6 attacks", False),
    ("vlan_hopping", "modules.vlan_hopping", "VLANHoppingModule", "exploit", EXPLOIT, "VLAN hopping", False),
    ("vpn_attacks", "modules.vpn_attacks", "VPNAttackModule", "exploit", EXPLOIT, "VPN attacks", False),
    ("dhcp_attacks", "modules.dhcp_attacks", "DHCPAttackModule", "exploit", EXPLOIT, "DHCP attacks", False),
    ("arp_attacks", "modules.arp_attacks", "ARPAttackModule", "exploit", EXPLOIT, "ARP attacks", False),
    ("icmp_attacks", "modules.icmp_attacks", "ICMPAttackModule", "exploit", EXPLOIT, "ICMP attacks", False),
    ("container_escape", "modules.container_escape", "ContainerEscapeModule", "exploit", EXPLOIT, "Container escape checks", False),
    ("cicd_injection", "modules.cicd_injection", "CICDInjectionModule", "exploit", EXPLOIT, "CI/CD injection", False),
    ("aws_iam_privesc", "modules.aws_iam_privesc", "AWSIAMPrivescModule", "exploit", EXPLOIT, "AWS IAM privilege escalation", False),
    ("ics_protocols", "modules.ics_protocols", "ICSProtocolModule", "exploit", EXPLOIT, "ICS and OT protocol checks", False),
    ("covert_channels", "modules.covert_channels", "CovertChannelModule", "exploit", EXPLOIT, "Covert channels", False),
    ("credential_dump", "modules.credential_dump", "CredentialDumpModule", "exploit", EXPLOIT, "Credential dumping", False),
    ("lateral_movement", "modules.lateral_movement", "LateralMovementModule", "exploit", EXPLOIT, "Lateral movement", False),
    ("ad_attacks", "modules.ad_attacks", "ADAttackModule", "exploit", EXPLOIT, "Active Directory attacks", False),
    ("coverage_fuzz", "modules.coverage_fuzz", "CoverageFuzzModule", "exploit", EXPLOIT, "Coverage-guided fuzzing", False),
    ("symbolic_exec", "modules.symbolic_exec", "SymbolicExecModule", "exploit", EXPLOIT, "Symbolic execution", False),
]

_OVERRIDES = {
    "race_condition": {"dest": "race", "flag": "--race", "aliases": ("--race-condition",)},
    "deserialization": {"dest": "deser", "flag": "--deser", "aliases": ("--deserialization",)},
    "fuzzer": {"dest": "fuzz", "flag": "--fuzz", "aliases": ("--fuzzer",)},
    "cache_poisoning": {"dest": "cache_poison", "flag": "--cache-poison", "aliases": ("--cache-poisoning",)},
    "firewall_bypass": {"dest": "firewall_bypass", "flag": "--firewall-bypass", "aliases": ("--fw-bypass",)},
}


def _build():
    specs = []
    for key, module, class_name, tier, modes, help, web_full in _ROWS:
        extra = _OVERRIDES.get(key, {})
        specs.append(
            _spec(
                key, module, class_name, tier, modes, help,
                web_full=web_full, **extra,
            )
        )
    return tuple(specs)


SPECS = _build()
_BY_KEY = {spec.key: spec for spec in SPECS}
ALL_MODULE_KEYS = tuple(spec.key for spec in SPECS)


def specs():
    return SPECS


def import_map():
    """Key to (module path, class name) for ``AtomicEngine._load_modules``."""
    return {spec.key: (spec.module, spec.class_name) for spec in SPECS}


def select(mode, flagged):
    """Return catalog key to bool.

    ``flagged(dest)`` is true when the operator passed that module's flag.
    ``mode`` is one of quick, standard, deep, cli_full, atomic_full,
    point_to_point, or individual (flags only).
    """
    out = {}
    for spec in SPECS:
        out[spec.key] = bool(flagged(spec.dest)) or (mode in spec.modes)
    return out


def profile_modules(name):
    mode = {"quick": "quick", "standard": "standard", "deep": "deep", "full": "atomic_full"}[name]
    return select(mode, lambda _dest: False)


def web_full_keys():
    return [spec.key for spec in SPECS if spec.web_full]


def add_missing_flags(parser):
    """Register catalog flags the parser does not already define."""
    taken = set()
    for action in parser._actions:
        taken.update(getattr(action, "option_strings", ()) or ())
    group = parser.add_argument_group("Catalog modules")
    added = False
    for spec in SPECS:
        names = (spec.flag, *spec.aliases)
        if any(name in taken for name in names):
            continue
        group.add_argument(*names, action="store_true", dest=spec.dest, help=spec.help)
        taken.update(names)
        added = True
    if not added and group in getattr(parser, "_action_groups", []):
        # Keep the help text quiet when every flag was already declared.
        parser._action_groups.remove(group)
    return parser
