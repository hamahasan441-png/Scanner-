"""
Scan profiles for the ``atomic`` wrapper.

A profile is a *named, tested, pre-blessed combination* of
``main.py`` flags that produces a known-good scan. Profiles are
deliberately conservative: aggressive options (auto-attack, shell
upload, brute force) are off by default and require ``--authorized``
PLUS ``profile=full`` to enable.
"""
from __future__ import annotations
import os
from dataclasses import dataclass, field
from typing import List, Dict, Any


@dataclass(frozen=True)
class Profile:
    """A safe-by-default scan configuration."""
    name: str
    description: str
    modules: Dict[str, bool]
    threads: int
    depth: int
    timeout: int
    delay: float
    evasion: str           # none | low | medium | high | insane | stealth
    waf_bypass: bool
    auto_external_tools: bool
    auto_attack: bool      # requires --authorized
    shell_upload: bool     # requires --authorized
    db_dump: bool          # requires --authorized
    brute_force: bool      # requires --authorized


# Module keys are exactly the keys in core/engine.py:_load_modules().
# Anything not listed here is OFF for that profile.
ALL_MODULE_KEYS = [
    "sqli", "xss", "lfi", "cmdi", "ssrf", "ssti", "xxe", "idor", "nosql",
    "cors", "jwt", "upload", "open_redirect", "crlf", "hpp", "graphql",
    "proto_pollution", "race_condition", "websocket", "deserialization",
    "osint", "fuzzer", "cloud_scan", "oauth", "mfa_bypass",
    "api_versioning", "dep_confusion", "llm_logic", "h2_smuggling",
    "cache_poisoning", "api_abuse", "deep_scan", "gatebreaker",
    "firewall_bypass",
]

# Always-on discovery / recon (no exploit risk).
DISCOVERY_KEYS = ["recon", "discovery", "shield_detect", "real_ip",
                  "passive_recon", "enrich", "exploit_search",
                  "attack_map", "chain_detect", "agent_scan"]


def _base(**mods: bool) -> Dict[str, bool]:
    """Build a module dict with everything off except the requested ones."""
    out: Dict[str, bool] = {k: False for k in ALL_MODULE_KEYS}
    out.update(mods)
    return out


PROFILES: Dict[str, Profile] = {
    "quick": Profile(
        name="quick",
        description="Fastest scan — high-signal modules only, no evasion, no recon.",
        modules=_base(sqli=True, xss=True, lfi=True, cmdi=True, ssrf=True),
        threads=10, depth=2, timeout=10, delay=0.0, evasion="none",
        waf_bypass=False, auto_external_tools=False,
        auto_attack=False, shell_upload=False, db_dump=False,
        brute_force=False,
    ),
    "standard": Profile(
        name="standard",
        description="Balanced scan — web app vulns + light recon, low evasion.",
        modules=_base(
            sqli=True, xss=True, lfi=True, cmdi=True, ssrf=True,
            ssti=True, xxe=True, idor=True, nosql=True, cors=True,
            jwt=True, open_redirect=True, crlf=True, hpp=True,
        ),
        threads=25, depth=3, timeout=15, delay=0.1, evasion="low",
        waf_bypass=False, auto_external_tools=False,
        auto_attack=False, shell_upload=False, db_dump=False,
        brute_force=False,
    ),
    "deep": Profile(
        name="deep",
        description="All web app modules + recon, WAF bypass, origin-IP discovery.",
        modules=_base(
            sqli=True, xss=True, lfi=True, cmdi=True, ssrf=True,
            ssti=True, xxe=True, idor=True, nosql=True, cors=True,
            jwt=True, upload=True, open_redirect=True, crlf=True, hpp=True,
            graphql=True, proto_pollution=True, race_condition=True,
            websocket=True, deserialization=True, osint=True, fuzzer=True,
            cloud_scan=True, h2_smuggling=True, cache_poisoning=True,
            api_abuse=True, deep_scan=True, gatebreaker=True,
            firewall_bypass=True,
        ),
        threads=50, depth=4, timeout=20, delay=0.2, evasion="medium",
        waf_bypass=True, auto_external_tools=True,
        auto_attack=False, shell_upload=False, db_dump=False,
        brute_force=False,
    ),
    "full": Profile(
        name="full",
        description=(
            "All 32 modules + recon + auto-attack. "
            "REQUIRES --authorized. Use only against targets you are "
            "explicitly permitted to test."
        ),
        modules=_base(
            sqli=True, xss=True, lfi=True, cmdi=True, ssrf=True,
            ssti=True, xxe=True, idor=True, nosql=True, cors=True,
            jwt=True, upload=True, open_redirect=True, crlf=True, hpp=True,
            graphql=True, proto_pollution=True, race_condition=True,
            websocket=True, deserialization=True, osint=True, fuzzer=True,
            cloud_scan=True, oauth=True, mfa_bypass=True,
            api_versioning=True, dep_confusion=True, llm_logic=True,
            h2_smuggling=True, cache_poisoning=True, api_abuse=True,
            deep_scan=True, gatebreaker=True, firewall_bypass=True,
        ),
        threads=100, depth=5, timeout=30, delay=0.25, evasion="high",
        waf_bypass=True, auto_external_tools=True,
        auto_attack=True, shell_upload=True, db_dump=True,
        brute_force=True,
    ),
}


def get(name: str) -> Profile:
    if name not in PROFILES:
        raise SystemExit(
            f"Unknown profile: {name!r}\n"
            f"Available: {', '.join(PROFILES)}"
        )
    return PROFILES[name]


def to_main_args(profile: Profile, target: str, authorized: bool) -> List[str]:
    """Translate a profile into a ``python main.py`` argv list."""
    args = ["main.py"]

    # Required.
    args += ["-t", target]
    args += ["-T", str(profile.threads)]
    args += ["-d", str(profile.depth)]
    args += ["--timeout", str(profile.timeout)]
    args += ["--delay", str(profile.delay)]
    args += ["--evasion", profile.evasion]

    # Module enable flags. main.py uses a different naming convention
    # than the engine module keys; map them here.
    mod_map = {
        "sqli": "--sqli", "xss": "--xss", "lfi": "--lfi", "cmdi": "--cmdi",
        "ssrf": "--ssrf", "ssti": "--ssti", "xxe": "--xxe", "idor": "--idor",
        "nosql": "--nosql", "cors": "--cors", "jwt": "--jwt",
        "upload": "--upload", "open_redirect": "--open-redirect",
        "crlf": "--crlf", "hpp": "--hpp", "graphql": "--graphql",
        "proto_pollution": "--proto-pollution",
        "race_condition": "--race-condition", "websocket": "--websocket",
        "deserialization": "--deserialization", "osint": "--osint",
        "fuzzer": "--fuzzer", "cloud_scan": "--cloud-scan",
        "oauth": "--oauth", "mfa_bypass": "--mfa-bypass",
        "api_versioning": "--api-versioning",
        "dep_confusion": "--dep-confusion", "llm_logic": "--llm-logic",
        "h2_smuggling": "--h2-smuggling",
        "cache_poisoning": "--cache-poisoning", "api_abuse": "--api-abuse",
        "deep_scan": "--deep-scan", "gatebreaker": "--gatebreaker",
        "firewall_bypass": "--firewall-bypass",
    }
    for key, flag in mod_map.items():
        if profile.modules.get(key):
            args.append(flag)

    # Discovery / recon (always on for quick+, all on for deep/full).
    args.append("--recon")
    if profile.name in ("standard", "deep", "full"):
        args.append("--discovery")
    if profile.name in ("deep", "full"):
        args.append("--passive-recon")
        args.append("--real-ip")
        args.append("--shield-detect")
        args.append("--enrich")
        args.append("--exploit-search")
        args.append("--attack-map")

    # WAF bypass & external tools.
    if profile.waf_bypass:
        args.append("--waf-bypass")
    if profile.auto_external_tools:
        args.append("--auto-external-tools")

    # Dangerous post-exploit — gated behind --authorized + profile=full.
    if profile.auto_attack and authorized:
        args.append("--auto-exploit")
    if profile.shell_upload and authorized:
        args.append("--shell")
    if profile.db_dump and authorized:
        args.append("--dump")
    if profile.brute_force and authorized:
        args.append("--brute")

    # Output.
    args += ["--format", "html,json"]
    atomic_home = os.environ.get("ATOMIC_HOME", "").strip()
    if not atomic_home:
        atomic_home = os.path.join(os.path.expanduser("~"), ".atomic")
    args += ["--output-dir", os.path.join(atomic_home, "reports")]

    return args
