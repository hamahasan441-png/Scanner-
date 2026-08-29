"""Managed, integrity-aware runtime for bundled security tools.

The framework prefers binaries shipped under ``runtime/bin``. Host PATH
resolution remains an explicit compatibility fallback so existing installs do
not break, but it is disabled when ``ATOMIC_REQUIRE_BUNDLED_TOOLS=1`` is set.

No tool is executed until its executable path has been resolved and, when a
manifest entry supplies a SHA-256, its integrity has been verified.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional


@dataclass(frozen=True)
class ToolSpec:
    name: str
    version: str = ""
    sha256: str = ""
    binary: str = ""
    platforms: tuple[str, ...] = ()
    # Manifest provenance.  ``portable_wrapper`` marks the bundled
    # *simulation* stubs (runtime/bin wrappers emitting canned output),
    # which must never be treated as real security tools by default.
    source: str = ""


def simulated_tools_allowed() -> bool:
    """SEC-013: simulation stubs are opt-in.

    The bundled ``portable_wrapper`` artifacts fabricate tool output
    (fake open ports, fake nuclei hits).  They are disabled by default so
    scans never report fabricated data as real; set
    ``ATOMIC_ALLOW_SIMULATED_TOOLS=1`` to enable them (demo/offline mode).
    """
    return os.environ.get("ATOMIC_ALLOW_SIMULATED_TOOLS", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


class ToolRuntime:
    def __init__(self, base_dir: Optional[str] = None):
        root = Path(base_dir or Path(__file__).resolve().parents[1])
        self.root = root
        self.bin_dir = root / "runtime" / "bin"
        self.manifest_path = root / "runtime" / "metadata" / "tools.json"
        # Workable default: allow host tools for usability so framework can use
        # installed security tools in jobs/tasks immediately. Secure mode opt-in:
        #   ATOMIC_REQUIRE_BUNDLED_TOOLS=1  → require verified bundled binaries only
        #   ATOMIC_ALLOW_HOST_TOOLS=0/false → disallow host fallback (fail-closed)
        # This balances security (explicit secure mode) with usability (default workable).
        req_bundled_env = os.environ.get("ATOMIC_REQUIRE_BUNDLED_TOOLS", "").lower()
        allow_env = os.environ.get("ATOMIC_ALLOW_HOST_TOOLS", "").lower()

        if req_bundled_env in {"1", "true", "yes", "on"}:
            # Strict secure mode: only verified bundled binaries
            self.allow_host_tools = False
            self.require_bundled = True
        elif allow_env in {"0", "false", "no", "off"}:
            # Explicitly disallow host tools
            self.allow_host_tools = False
            self.require_bundled = True
        elif allow_env in {"1", "true", "yes", "on"}:
            # Explicitly allow host tools (legacy opt-in)
            self.allow_host_tools = True
            self.require_bundled = False
        else:
            # Default workable: allow host tools with warning (portable mode)
            # This makes framework use nmap, nuclei, etc from PATH if present
            self.allow_host_tools = True
            self.require_bundled = False
        self._manifest = self._load_manifest()

    def _load_manifest(self) -> Dict[str, ToolSpec]:
        if not self.manifest_path.is_file():
            return {}
        try:
            data = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return {}
        specs = {}
        for name, raw in (data.get("tools", {}) if isinstance(data, dict) else {}).items():
            if not isinstance(raw, dict):
                continue
            specs[name] = ToolSpec(
                name=name,
                version=str(raw.get("version", "")),
                sha256=str(raw.get("sha256", "")).lower(),
                binary=str(raw.get("binary", name)),
                platforms=tuple(raw.get("platforms", ()) or ()),
                source=str(raw.get("source", "")),
            )
        return specs

    def is_simulated(self, name: str) -> bool:
        """True when the manifest entry for *name* is a simulation stub."""
        spec = self._manifest.get(name)
        return bool(spec and spec.source == "portable_wrapper")

    def is_effectively_simulated(self, name: str) -> bool:
        """True only when the binary that would actually execute is a stub.

        A real host installation of the same tool wins over the manifest
        classification: if ``resolve()`` lands on a host binary, the tool is
        real even though a wrapper entry exists in the manifest.
        """
        if not self.is_simulated(name):
            return False
        bundled = self.bundled_path(name)
        if not bundled:
            return False
        return self.resolve(name) == bundled

    @staticmethod
    def _platform_key() -> str:
        system = platform.system().lower()
        machine = platform.machine().lower().replace("amd64", "x86_64")
        return f"{system}-{machine}"

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def bundled_path(self, name: str) -> Optional[str]:
        spec = self._manifest.get(name, ToolSpec(name=name, binary=name))
        # SECURITY FIX (SEC-013): simulation stubs are never resolved unless
        # explicitly enabled.  Their hash verifies *the stub itself*, which
        # previously made fabricated output appear as a "verified" real tool
        # and — via engine findings conversion — produced fabricated findings.
        if spec.source == "portable_wrapper" and not simulated_tools_allowed():
            return None
        path = (self.bin_dir / spec.binary).resolve()
        try:
            path.relative_to(self.bin_dir.resolve())
        except ValueError:
            return None
        if not path.is_file() or not os.access(path, os.X_OK):
            return None
        if spec.platforms and self._platform_key() not in spec.platforms:
            return None
        # A bundled executable is trusted only when the manifest pins its
        # digest.  An empty digest means "artifact not provisioned", not
        # "implicitly trusted".
        if not spec.sha256 or not re.fullmatch(r"[0-9a-f]{64}", spec.sha256):
            return None
        if self._sha256(path) != spec.sha256:
            return None
        return str(path)

    def resolve(self, name: str) -> Optional[str]:
        bundled = self.bundled_path(name)
        if bundled:
            return bundled
        if self.require_bundled:
            return None
        return shutil.which(name)

    def status(self) -> Dict[str, dict]:
        # Include all known tools from manifests and common security tools
        names = set(self._manifest)
        # ToolIntegrator + ReconArsenal + extra
        names.update({
            "nmap", "nuclei", "nikto", "whatweb", "subfinder", "httpx", "ffuf",
            "amass", "dnsx", "katana", "naabu", "interactsh-client",
            "gau", "waybackurls", "gobuster", "feroxbuster", "masscan",
            "rustscan", "hakrawler", "arjun", "paramspider", "dirsearch",
            "whatweb", "subfinder", "httpx", "ffuf", "amass", "katana"
        })
        out = {}
        for name in sorted(names):
            bundled = self.bundled_path(name)
            host = shutil.which(name)
            simulated = self.is_simulated(name)
            out[name] = {
                "available": bool(bundled or (host and self.allow_host_tools)),
                "source": "bundled" if bundled else ("host" if host and self.allow_host_tools else "none"),
                "integrity": "verified" if bundled else ("unverified-host" if host and self.allow_host_tools else "missing"),
                "bundled_path": bundled,
                "host_path": host,
                # SEC-013: transparent provenance — dashboards/APIs must be
                # able to tell real tools from bundled simulation stubs.
                "simulated": simulated,
                "simulation_disabled_by_default": bool(
                    simulated and not simulated_tools_allowed() and not (host and self.allow_host_tools)
                ),
            }
        return out

    def make_portable(self, tools: Optional[list] = None) -> Dict[str, dict]:
        """Make host tools portable by copying them to runtime/bin and updating manifest with sha256.

        This creates verified bundled binaries from currently installed host tools,
        turning unverified-host into verified portable artifacts.

        Args:
            tools: Optional list of tool names to make portable. If None, all found host tools.

        Returns:
            Dict mapping tool name to result info.
        """
        import shutil as _shutil
        self.bin_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_path.parent.mkdir(parents=True, exist_ok=True)

        # Load existing manifest or create new
        manifest_data = {}
        if self.manifest_path.is_file():
            try:
                manifest_data = json.loads(self.manifest_path.read_text(encoding="utf-8"))
            except Exception:
                manifest_data = {}
        if "tools" not in manifest_data:
            manifest_data["tools"] = {}
        if "schema_version" not in manifest_data:
            manifest_data["schema_version"] = 1

        # Determine which tools to process
        all_status = self.status()
        if tools is None:
            # All tools that are available on host but not yet bundled
            tools_to_process = [name for name, info in all_status.items() if info.get("host_path")]
        else:
            tools_to_process = tools

        results = {}
        for name in tools_to_process:
            host_path = _shutil.which(name)
            if not host_path:
                results[name] = {"success": False, "error": "not found on host"}
                continue
            try:
                src = Path(host_path)
                dest = self.bin_dir / name
                # Copy file, preserve executable
                _shutil.copy2(src, dest)
                # Ensure executable
                dest.chmod(0o755)
                # Compute sha256
                sha256 = self._sha256(dest)
                # Update manifest
                plat_key = self._platform_key()
                existing = manifest_data["tools"].get(name, {})
                manifest_data["tools"][name] = {
                    "version": existing.get("version", "portable"),
                    "binary": name,
                    "sha256": sha256,
                    "platforms": list(set(existing.get("platforms", []) + [plat_key])),
                    "source": f"host:{host_path}",
                }
                results[name] = {"success": True, "sha256": sha256, "bundled_path": str(dest), "host_path": host_path}
            except Exception as exc:
                results[name] = {"success": False, "error": str(exc)}

        # Write updated manifest
        try:
            self.manifest_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")
            # Reload manifest
            self._manifest = self._load_manifest()
        except Exception as exc:
            for r in results.values():
                if r.get("success"):
                    r["manifest_error"] = str(exc)

        return results

    def install_missing(self) -> Dict[str, dict]:
        """Install missing tools using tool_downloader if available.

        Attempts to use Go, apt, brew, pip etc to install tools.
        Returns status dict.
        """
        try:
            from utils.tool_downloader import TOOL_REGISTRY, _is_tool_installed, install_tool
            results = {}
            for tool_name in TOOL_REGISTRY:
                if _is_tool_installed(tool_name):
                    results[tool_name] = {"installed": True, "method": "already"}
                else:
                    # Try to install
                    ok = install_tool(tool_name, verbose=False)
                    results[tool_name] = {"installed": ok, "method": "auto"}
            return results
        except Exception as exc:
            return {"error": str(exc)}


RUNTIME = ToolRuntime()


def resolve_tool(name: str) -> Optional[str]:
    return RUNTIME.resolve(name)


def is_simulated_tool(name: str) -> bool:
    """Module-level helper: would executing *name* run a simulation stub?"""
    return RUNTIME.is_effectively_simulated(name)
