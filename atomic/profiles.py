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
from dataclasses import dataclass
from typing import Dict, List

from module_catalog import ALL_MODULE_KEYS, profile_modules, specs


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


# Attack-module switches come from module_catalog. Discovery flags below
# are pipeline stages, not engine modules.
# Always-on discovery / recon (no exploit risk).
DISCOVERY_KEYS = ["recon", "discovery", "shield_detect", "real_ip",
                  "passive_recon", "enrich", "exploit_search",
                  "attack_map", "chain_detect", "agent_scan"]


PROFILES: Dict[str, Profile] = {
    "quick": Profile(
        name="quick",
        description="Fastest scan — high-signal modules only, no evasion, no recon.",
        modules=profile_modules("quick"),
        threads=10, depth=2, timeout=10, delay=0.0, evasion="none",
        waf_bypass=False, auto_external_tools=False,
        auto_attack=False, shell_upload=False, db_dump=False,
        brute_force=False,
    ),
    "standard": Profile(
        name="standard",
        description="Balanced scan — web app vulns + light recon, low evasion.",
        modules=profile_modules("standard"),
        threads=25, depth=3, timeout=15, delay=0.1, evasion="low",
        waf_bypass=False, auto_external_tools=False,
        auto_attack=False, shell_upload=False, db_dump=False,
        brute_force=False,
    ),
    "deep": Profile(
        name="deep",
        description="All web app modules + recon, WAF bypass, origin-IP discovery.",
        modules=profile_modules("deep"),
        threads=50, depth=4, timeout=20, delay=0.2, evasion="medium",
        waf_bypass=True, auto_external_tools=True,
        auto_attack=False, shell_upload=False, db_dump=False,
        brute_force=False,
    ),
    "full": Profile(
        name="full",
        description=(
            "Every registered engine module, including exploit-tier checks, "
            "plus recon and auto-attack. REQUIRES --authorized. Use only "
            "against targets you are explicitly permitted to test."
        ),
        modules=profile_modules("full"),
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

    # Flags are the catalog's canonical spellings, which main.py accepts
    # (including the short forms such as --race and --fuzz).
    for spec in specs():
        if profile.modules.get(spec.key):
            args.append(spec.flag)

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

    # WAF bypass. auto_external_tools is always on inside main.py and that
    # entry point has no flag for it, so emitting one would abort the run.
    if profile.waf_bypass:
        args.append("--waf-bypass")

    # Dangerous post-exploit — gated behind --authorized + profile=full.
    if profile.auto_attack and authorized:
        args.append("--auto-exploit")
    if profile.shell_upload and authorized:
        args.append("--shell")
    if profile.db_dump and authorized:
        args.append("--dump")
    if profile.brute_force and authorized:
        args.append("--brute")

    # Output. main.py accepts --format as a single choice and --output
    # (not --output-dir) for the report directory.
    args += ["--format", "html"]
    atomic_home = os.environ.get("ATOMIC_HOME", "").strip()
    if not atomic_home:
        atomic_home = os.path.join(os.path.expanduser("~"), ".atomic")
    args += ["--output", os.path.join(atomic_home, "reports")]

    return args
