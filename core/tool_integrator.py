#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - External Tool Integration Layer
Integrates with industry-standard security tools when available:
  - Nmap       (network scanning, service detection)
  - Nuclei     (template-based vulnerability scanning)
  - Nikto      (web server assessment)
  - WhatWeb    (technology fingerprinting)
  - Subfinder  (subdomain enumeration)
  - Httpx      (HTTP probing, tech detection)
  - Ffuf       (web fuzzing, directory brute-forcing)

Each tool adapter follows a common interface:
  .is_available() → bool
  .run(target, **opts) → ToolResult
"""

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from core.tool_runtime import resolve_tool


@dataclass
class ToolResult:
    """Standard result from an external tool execution."""

    tool: str
    target: str
    success: bool
    exit_code: int = 0
    raw_output: str = ""
    parsed_data: dict = field(default_factory=dict)
    findings: List[dict] = field(default_factory=list)
    duration_seconds: float = 0.0
    timestamp: str = ""
    error: str = ""
    # SEC-013: True when the output came from a bundled simulation stub
    # (portable wrapper) instead of the real tool.  Consumers must not
    # present simulated output as real scan evidence.
    simulated: bool = False

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "target": self.target,
            "success": self.success,
            "exit_code": self.exit_code,
            "findings_count": len(self.findings),
            "findings": self.findings,
            "parsed_data": self.parsed_data,
            "duration_seconds": self.duration_seconds,
            "timestamp": self.timestamp,
            "error": self.error,
            "simulated": self.simulated,
        }


def _is_safe_target_arg(arg: str) -> bool:
    """Return True if *arg* looks like a safe hostname / URL / IP, not a flag injection.

    Rejects:
    - Args starting with '-' (option injection)
    - Args containing shell metacharacters, control chars, or spaces in domain context
    - Args longer than 2048 chars
    """
    if not isinstance(arg, str) or not arg:
        return False
    if len(arg) > 2048:
        return False
    # Must not look like an option flag
    if arg.startswith("-"):
        return False
    # Must not contain shell metacharacters or control chars
    if any(c in arg for c in [";", "&", "|", "`", "$", "\n", "\r", "\x00"]):
        return False
    return True


def _sanitize_tool_cmd(cmd: list) -> tuple[bool, str]:
    """Validate that no positional argument in *cmd* is an option injection.

    The first element is executable name, subsequent elements are flags or targets.
    We allow known flags (starting with '-') only if they are from an allowlist
    of expected flags per tool. For generic validation, we reject any arg after
    a target flag that starts with '-'.
    Returns (ok, error_message).
    """
    # Expected flag prefixes for our toolset
    known_flags = {
        "-d", "-u", "-t", "-h", "-F", "-T4", "-sV", "-sC", "-p", "-oX",
        "-Pn", "--script", "-O", "-p-", "-jsonl", "-silent", "-severity",
        "-tags", "-Format", "-o", "-Tuning", "--log-json=-", "-log-json",
        "-a", "-follow-redirects", "-path", "-status-code", "-content-length",
        "-title", "-tech-detect", "-server", "-json", "-w", "-e", "-fc",
        "-of", "-s", "--subs", "-o", "-of", "-w", "-e", "-fc", "-s", "--log-json"
    }
    # We only inspect args that look like domains/urls (positional)
    # For simplicity, reject any arg that is exactly a flag injection attempting
    # to masquerade as target but is actually starting with '-'.
    for i, arg in enumerate(cmd[1:], start=1):
        # If arg is known flag, ok
        if arg in known_flags or arg.startswith("-a"):
            continue
        # If arg contains '=', it's likely a flag with value, allow
        if "=" in arg and arg.startswith("-"):
            continue
        # If arg starts with '-', it's suspicious as positional
        if isinstance(arg, str) and arg.startswith("-") and len(arg) > 1:
            # Check if previous arg was a flag that expects a value, then this is value
            prev = cmd[i-1] if i-1 >= 0 else ""
            if prev in ("-d", "-u", "-t", "-h", "-p", "-oX", "-Format", "-o", "-Tuning", "-path", "-w", "-e", "-fc", "-t"):
                # This arg is supposed to be a value (e.g., domain). Reject if looks like flag.
                return False, f"Invalid target argument (flag injection): {arg!r}"
    return True, ""


def _run_command(cmd: list, timeout: int = 300, cwd: str = None, max_output_bytes: int = 5 * 1024 * 1024) -> tuple:
    """Run a tool with bounded output and managed executable resolution."""
    import time
    if not isinstance(cmd, list) or not cmd or not all(isinstance(x, str) for x in cmd):
        return -3, "", "invalid command", 0.0
    # SECURITY FIX (TOOL-001): Validate against argument injection
    ok, err = _sanitize_tool_cmd(cmd)
    if not ok:
        return -3, "", err, 0.0
    # Extra: validate target-like args (last args often target) not starting with '-'
    # For nmap, last arg is target; for others similar.
    if len(cmd) >= 2:
        # Heuristic: check last positional arg that is not a flag value for -
        last = cmd[-1]
        # If last arg is not a known flag and contains typical domain chars, validate
        if _is_safe_target_arg(last) is False and not last.startswith("/") and not last.startswith("-"):
            # Allow file paths like /dev/stdout, but reject flag-like
            if last.startswith("-"):
                return -3, "", f"Invalid target (flag injection): {last!r}", 0.0
    executable = resolve_tool(cmd[0]) if not os.path.isabs(cmd[0]) else cmd[0]
    if not executable:
        return -2, "", f"Command not found: {cmd[0]}", 0.0
    cmd = [executable, *cmd[1:]]
    start = time.time()
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=max(1, int(timeout)), cwd=cwd,
            check=False, env={k: v for k, v in os.environ.items() if k not in {"LD_PRELOAD", "PYTHONINSPECT", "PYTHONPATH"}},
        )
        duration = time.time() - start
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        truncated = False
        if len(stdout.encode("utf-8", "ignore")) > max_output_bytes:
            stdout = stdout.encode("utf-8", "ignore")[:max_output_bytes].decode("utf-8", "ignore")
            truncated = True
        if len(stderr.encode("utf-8", "ignore")) > max_output_bytes:
            stderr = stderr.encode("utf-8", "ignore")[:max_output_bytes].decode("utf-8", "ignore")
            truncated = True
        if truncated:
            stderr += "\n[output truncated by framework]"
        return result.returncode, stdout, stderr, duration
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout}s", time.time() - start
    except FileNotFoundError:
        return -2, "", f"Command not found: {cmd[0]}", 0.0
    except (OSError, subprocess.SubprocessError) as exc:
        return -3, "", str(exc), time.time() - start


# ---------------------------------------------------------------------------
# Nmap Adapter
# ---------------------------------------------------------------------------
class NmapAdapter:
    """Integration with Nmap network scanner."""

    TOOL_NAME = "nmap"

    def is_available(self) -> bool:
        return resolve_tool("nmap") is not None

    def run(self, target: str, ports: str = "1-1000", scan_type: str = "service", timeout: int = 300) -> ToolResult:
        """Run an Nmap scan.

        Args:
            target: IP address or hostname.
            ports: Port specification (e.g., '80,443' or '1-1000').
            scan_type: 'quick', 'service', 'vuln', or 'full'.
            timeout: Max seconds.
        """
        # SECURITY: Validate target to prevent argument injection
        if not _is_safe_target_arg(target):
            return ToolResult(tool=self.TOOL_NAME, target=target, success=False, error="Invalid target (flag injection or unsafe)")
        if not self.is_available():
            return ToolResult(tool=self.TOOL_NAME, target=target, success=False, error="nmap not installed")

        cmd = ["nmap", "-Pn"]
        if scan_type == "quick":
            cmd += ["-F", "-T4"]
        elif scan_type == "service":
            cmd += ["-sV", "-sC", "-p", ports]
        elif scan_type == "vuln":
            cmd += ["-sV", "--script", "vuln", "-p", ports]
        elif scan_type == "full":
            cmd += ["-sV", "-sC", "-O", "-p-", "-T4"]
        else:
            cmd += ["-sV", "-p", ports]

        # Use XML output for parsing
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            xml_path = tmp.name
        cmd += ["-oX", xml_path, target]

        exit_code, stdout, stderr, duration = _run_command(cmd, timeout=timeout)

        result = ToolResult(
            tool=self.TOOL_NAME,
            target=target,
            success=exit_code == 0,
            exit_code=exit_code,
            raw_output=stdout,
            duration_seconds=round(duration, 2),
            timestamp=datetime.now(timezone.utc).isoformat(),
            error=stderr if exit_code != 0 else "",
        )

        # Parse XML output
        try:
            if os.path.isfile(xml_path):
                result.parsed_data = self._parse_xml(xml_path)
                result.findings = self._extract_findings(result.parsed_data)
        finally:
            if os.path.isfile(xml_path):
                os.unlink(xml_path)

        return result

    def _parse_xml(self, xml_path: str) -> dict:
        """Parse Nmap XML output into a structured dict."""
        try:
            import xml.etree.ElementTree as ET

            tree = ET.parse(xml_path)
            root = tree.getroot()
        except Exception:
            return {}

        hosts = []
        for host_elem in root.findall(".//host"):
            host_data = {"addresses": [], "ports": [], "os": []}

            for addr in host_elem.findall(".//address"):
                host_data["addresses"].append(
                    {
                        "addr": addr.get("addr", ""),
                        "addrtype": addr.get("addrtype", ""),
                    }
                )

            for port in host_elem.findall(".//port"):
                state = port.find("state")
                service = port.find("service")
                port_info = {
                    "port": port.get("portid", ""),
                    "protocol": port.get("protocol", ""),
                    "state": state.get("state", "") if state is not None else "",
                    "service": service.get("name", "") if service is not None else "",
                    "product": service.get("product", "") if service is not None else "",
                    "version": service.get("version", "") if service is not None else "",
                }
                # Check for script output (vuln results)
                scripts = []
                for script in port.findall(".//script"):
                    scripts.append(
                        {
                            "id": script.get("id", ""),
                            "output": script.get("output", "")[:500],
                        }
                    )
                port_info["scripts"] = scripts
                host_data["ports"].append(port_info)

            hosts.append(host_data)

        return {"hosts": hosts}

    def _extract_findings(self, parsed: dict) -> List[dict]:
        """Extract vulnerability findings from parsed Nmap data."""
        findings = []
        for host in parsed.get("hosts", []):
            addr = host["addresses"][0]["addr"] if host["addresses"] else "unknown"
            for port in host.get("ports", []):
                if port["state"] == "open":
                    findings.append(
                        {
                            "type": "open_port",
                            "host": addr,
                            "port": port["port"],
                            "protocol": port["protocol"],
                            "service": port["service"],
                            "product": port["product"],
                            "version": port["version"],
                        }
                    )
                for script in port.get("scripts", []):
                    if "vuln" in script["id"].lower() or "exploit" in script["output"].lower():
                        findings.append(
                            {
                                "type": "vulnerability",
                                "host": addr,
                                "port": port["port"],
                                "script": script["id"],
                                "details": script["output"][:300],
                            }
                        )
        return findings


# ---------------------------------------------------------------------------
# Nuclei Adapter
# ---------------------------------------------------------------------------
class NucleiAdapter:
    """Integration with ProjectDiscovery Nuclei scanner.

    Supports both community templates and ATOMIC Framework's built-in
    templates from ``nuclei_templates/`` directory.
    """

    TOOL_NAME = "nuclei"
    # Path to ATOMIC Framework's built-in nuclei templates
    _BUILTIN_TEMPLATES = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "nuclei_templates",
    )

    def is_available(self) -> bool:
        return resolve_tool("nuclei") is not None

    @classmethod
    def builtin_templates_path(cls) -> str:
        """Return the path to the built-in nuclei_templates/ directory."""
        return cls._BUILTIN_TEMPLATES

    @classmethod
    def list_builtin_templates(cls) -> List[str]:
        """List all built-in template YAML files."""
        templates = []
        tpl_dir = cls._BUILTIN_TEMPLATES
        if not os.path.isdir(tpl_dir):
            return templates
        for root, _dirs, files in os.walk(tpl_dir):
            for fname in sorted(files):
                if fname.endswith((".yaml", ".yml")):
                    templates.append(
                        os.path.relpath(
                            os.path.join(root, fname),
                            tpl_dir,
                        )
                    )
        return templates

    def run(
        self,
        target: str,
        templates: str = "",
        severity: str = "",
        tags: str = "",
        timeout: int = 600,
        use_builtin: bool = False,
    ) -> "ToolResult":
        """Run a Nuclei scan.

        Args:
            target: URL to scan.
            templates: Template directory or specific template path.
            severity: Filter by severity (critical, high, medium, low, info).
            tags: Filter templates by tags (e.g., 'cve,owasp').
            timeout: Max seconds.
            use_builtin: Also include ATOMIC Framework's built-in templates.
        """
        if not _is_safe_target_arg(target):
            return ToolResult(tool=self.TOOL_NAME, target=target, success=False, error="Invalid target (flag injection or unsafe)")

        if not self.is_available():
            return ToolResult(tool=self.TOOL_NAME, target=target, success=False, error="nuclei not installed")

        cmd = ["nuclei", "-u", target, "-jsonl", "-silent"]
        if templates:
            cmd += ["-t", templates]
        if use_builtin and os.path.isdir(self._BUILTIN_TEMPLATES):
            cmd += ["-t", self._BUILTIN_TEMPLATES]
        if severity:
            cmd += ["-severity", severity]
        if tags:
            cmd += ["-tags", tags]

        exit_code, stdout, stderr, duration = _run_command(cmd, timeout=timeout)

        result = ToolResult(
            tool=self.TOOL_NAME,
            target=target,
            success=exit_code == 0,
            exit_code=exit_code,
            raw_output=stdout,
            duration_seconds=round(duration, 2),
            timestamp=datetime.now(timezone.utc).isoformat(),
            error=stderr if exit_code != 0 else "",
        )

        result.findings = self._parse_jsonl(stdout)
        result.parsed_data = {"total_findings": len(result.findings)}
        return result

    def _parse_jsonl(self, output: str) -> List[dict]:
        """Parse Nuclei JSONL output."""
        findings = []
        for line in output.strip().split("\n"):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                findings.append(
                    {
                        "template_id": data.get("template-id", ""),
                        "name": data.get("info", {}).get("name", ""),
                        "severity": data.get("info", {}).get("severity", ""),
                        "type": data.get("type", ""),
                        "host": data.get("host", ""),
                        "matched_at": data.get("matched-at", ""),
                        "description": data.get("info", {}).get("description", "")[:300],
                        "reference": data.get("info", {}).get("reference", [])[:5],
                        "tags": data.get("info", {}).get("tags", []),
                    }
                )
            except (json.JSONDecodeError, AttributeError):
                continue
        return findings


# ---------------------------------------------------------------------------
# Nikto Adapter
# ---------------------------------------------------------------------------
class NiktoAdapter:
    """Integration with Nikto web server scanner."""

    TOOL_NAME = "nikto"

    def is_available(self) -> bool:
        return resolve_tool("nikto") is not None

    def run(self, target: str, tuning: str = "", timeout: int = 300) -> ToolResult:
        """Run a Nikto scan.

        Args:
            target: URL to scan.
            tuning: Scan tuning options (e.g., '123bde' for specific test types).
            timeout: Max seconds.
        """
        if not _is_safe_target_arg(target):
            return ToolResult(tool=self.TOOL_NAME, target=target, success=False, error="Invalid target (flag injection or unsafe)")

        if not self.is_available():
            return ToolResult(tool=self.TOOL_NAME, target=target, success=False, error="nikto not installed")

        cmd = ["nikto", "-h", target, "-Format", "json", "-o", "-"]
        if tuning:
            cmd += ["-Tuning", tuning]

        exit_code, stdout, stderr, duration = _run_command(cmd, timeout=timeout)

        result = ToolResult(
            tool=self.TOOL_NAME,
            target=target,
            success=exit_code == 0,
            exit_code=exit_code,
            raw_output=stdout,
            duration_seconds=round(duration, 2),
            timestamp=datetime.now(timezone.utc).isoformat(),
            error=stderr if exit_code != 0 else "",
        )

        result.findings = self._parse_output(stdout)
        result.parsed_data = {"total_findings": len(result.findings)}
        return result

    def _parse_output(self, output: str) -> List[dict]:
        """Parse Nikto JSON output."""
        findings = []
        try:
            data = json.loads(output)
            if isinstance(data, dict):
                vulns = data.get("vulnerabilities", [])
                for v in vulns:
                    findings.append(
                        {
                            "id": v.get("id", ""),
                            "method": v.get("method", ""),
                            "url": v.get("url", ""),
                            "msg": v.get("msg", ""),
                            "references": v.get("references", {}),
                        }
                    )
        except (json.JSONDecodeError, TypeError):
            # Fallback: parse text output
            for line in output.split("\n"):
                line = line.strip()
                if line.startswith("+") and ": " in line:
                    findings.append({"msg": line[2:], "type": "nikto_finding"})
        return findings


# ---------------------------------------------------------------------------
# WhatWeb Adapter
# ---------------------------------------------------------------------------
class WhatWebAdapter:
    """Integration with WhatWeb technology fingerprinting."""

    TOOL_NAME = "whatweb"

    def is_available(self) -> bool:
        return resolve_tool("whatweb") is not None

    def run(self, target: str, aggression: int = 1, timeout: int = 120) -> ToolResult:
        """Run WhatWeb fingerprinting.

        Args:
            target: URL to fingerprint.
            aggression: Aggression level (1=stealthy, 3=aggressive).
            timeout: Max seconds.
        """
        if not _is_safe_target_arg(target):
            return ToolResult(tool=self.TOOL_NAME, target=target, success=False, error="Invalid target (flag injection or unsafe)")

        if not self.is_available():
            return ToolResult(tool=self.TOOL_NAME, target=target, success=False, error="whatweb not installed")

        cmd = ["whatweb", "--log-json=-", f"-a{aggression}", target]

        exit_code, stdout, stderr, duration = _run_command(cmd, timeout=timeout)

        result = ToolResult(
            tool=self.TOOL_NAME,
            target=target,
            success=exit_code == 0,
            exit_code=exit_code,
            raw_output=stdout,
            duration_seconds=round(duration, 2),
            timestamp=datetime.now(timezone.utc).isoformat(),
            error=stderr if exit_code != 0 else "",
        )

        result.parsed_data = self._parse_json(stdout)
        result.findings = self._extract_technologies(result.parsed_data)
        return result

    def _parse_json(self, output: str) -> dict:
        """Parse WhatWeb JSON output."""
        technologies = []
        for line in output.strip().split("\n"):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                technologies.append(data)
            except json.JSONDecodeError:
                continue
        return {"entries": technologies}

    def _extract_technologies(self, parsed: dict) -> List[dict]:
        """Extract technology findings."""
        findings = []
        for entry in parsed.get("entries", []):
            plugins = entry.get("plugins", {})
            for name, info in plugins.items():
                finding = {
                    "technology": name,
                    "version": "",
                    "string": [],
                }
                if isinstance(info, dict):
                    finding["version"] = info.get("version", [""])[0] if info.get("version") else ""
                    finding["string"] = info.get("string", [])[:3]
                findings.append(finding)
        return findings


# ---------------------------------------------------------------------------
# Subfinder Adapter
# ---------------------------------------------------------------------------
class SubfinderAdapter:
    """Integration with ProjectDiscovery Subfinder for subdomain enumeration."""

    TOOL_NAME = "subfinder"

    def is_available(self) -> bool:
        return resolve_tool("subfinder") is not None

    def run(self, domain: str, timeout: int = 120) -> ToolResult:
        """Run subdomain enumeration.

        Args:
            domain: Domain to enumerate subdomains for.
            timeout: Max seconds.
        """
        if not self.is_available():
            return ToolResult(tool=self.TOOL_NAME, target=domain, success=False, error="subfinder not installed")
        # SECURITY: Validate domain to prevent argument injection
        if not _is_safe_target_arg(domain):
            return ToolResult(tool=self.TOOL_NAME, target=domain, success=False, error="Invalid domain (flag injection or unsafe)")

        cmd = ["subfinder", "-d", domain, "-silent"]

        exit_code, stdout, stderr, duration = _run_command(cmd, timeout=timeout)

        result = ToolResult(
            tool=self.TOOL_NAME,
            target=domain,
            success=exit_code == 0,
            exit_code=exit_code,
            raw_output=stdout,
            duration_seconds=round(duration, 2),
            timestamp=datetime.now(timezone.utc).isoformat(),
            error=stderr if exit_code != 0 else "",
        )

        subdomains = [s.strip() for s in stdout.strip().split("\n") if s.strip()]
        result.findings = [{"subdomain": s} for s in subdomains]
        result.parsed_data = {"total_subdomains": len(subdomains), "subdomains": subdomains}
        return result


# ---------------------------------------------------------------------------
# Httpx Adapter
# ---------------------------------------------------------------------------
class HttpxAdapter:
    """Integration with ProjectDiscovery Httpx for HTTP probing."""

    TOOL_NAME = "httpx"

    def is_available(self) -> bool:
        return resolve_tool("httpx") is not None

    def run(
        self, target: str, paths: Optional[List[str]] = None, follow_redirects: bool = True, timeout: int = 120
    ) -> ToolResult:
        """Run HTTP probing with Httpx.

        Args:
            target: URL or domain to probe.
            paths: Optional list of paths to check.
            follow_redirects: Whether to follow HTTP redirects.
            timeout: Max seconds.
        """
        if not _is_safe_target_arg(target):
            return ToolResult(tool=self.TOOL_NAME, target=target, success=False, error="Invalid target (flag injection or unsafe)")

        if not self.is_available():
            return ToolResult(tool=self.TOOL_NAME, target=target, success=False, error="httpx not installed")

        cmd = [
            "httpx",
            "-u",
            target,
            "-json",
            "-silent",
            "-status-code",
            "-content-length",
            "-title",
            "-tech-detect",
            "-server",
        ]
        if follow_redirects:
            cmd.append("-follow-redirects")
        if paths:
            cmd += ["-path", ",".join(paths)]

        exit_code, stdout, stderr, duration = _run_command(cmd, timeout=timeout)

        result = ToolResult(
            tool=self.TOOL_NAME,
            target=target,
            success=exit_code == 0,
            exit_code=exit_code,
            raw_output=stdout,
            duration_seconds=round(duration, 2),
            timestamp=datetime.now(timezone.utc).isoformat(),
            error=stderr if exit_code != 0 else "",
        )

        result.findings = self._parse_jsonl(stdout)
        result.parsed_data = {"total_probed": len(result.findings)}
        return result

    def _parse_jsonl(self, output: str) -> List[dict]:
        """Parse Httpx JSONL output."""
        findings = []
        for line in output.strip().split("\n"):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                findings.append(
                    {
                        "url": data.get("url", ""),
                        "status_code": data.get("status_code", 0),
                        "title": data.get("title", ""),
                        "content_length": data.get("content_length", 0),
                        "technologies": data.get("tech", []),
                        "server": data.get("webserver", ""),
                        "content_type": data.get("content_type", ""),
                        "host": data.get("host", ""),
                    }
                )
            except (json.JSONDecodeError, AttributeError):
                continue
        return findings


# ---------------------------------------------------------------------------
# Ffuf Adapter
# ---------------------------------------------------------------------------
class FfufAdapter:
    """Integration with ffuf for web fuzzing and directory brute-forcing."""

    TOOL_NAME = "ffuf"

    def is_available(self) -> bool:
        return resolve_tool("ffuf") is not None

    def run(
        self, target: str, wordlist: str = "", extensions: str = "", filter_codes: str = "404", timeout: int = 300
    ) -> ToolResult:
        """Run ffuf web fuzzing.

        Args:
            target: URL with FUZZ keyword (e.g. ``https://target.com/FUZZ``).
            wordlist: Path to wordlist file.
            extensions: Comma-separated extensions (e.g. ``php,html,txt``).
            filter_codes: HTTP status codes to filter out.
            timeout: Max seconds.
        """
        if not _is_safe_target_arg(target):
            return ToolResult(tool=self.TOOL_NAME, target=target, success=False, error="Invalid target (flag injection or unsafe)")

        if not self.is_available():
            return ToolResult(tool=self.TOOL_NAME, target=target, success=False, error="ffuf not installed")

        # Ensure FUZZ keyword is present
        fuzz_url = target if "FUZZ" in target else f'{target.rstrip("/")}/FUZZ'

        cmd = ["ffuf", "-u", fuzz_url, "-o", "/dev/stdout", "-of", "json", "-s"]
        if wordlist:
            cmd += ["-w", wordlist]
        else:
            # Read wordlist from stdin (caller must pipe data, or ffuf
            # exits immediately).  Prefer passing an explicit wordlist
            # path via the ``wordlist`` argument.
            cmd += ["-w", "-"]
        if extensions:
            cmd += ["-e", extensions]
        if filter_codes:
            cmd += ["-fc", filter_codes]

        exit_code, stdout, stderr, duration = _run_command(cmd, timeout=timeout)

        result = ToolResult(
            tool=self.TOOL_NAME,
            target=target,
            success=exit_code == 0,
            exit_code=exit_code,
            raw_output=stdout,
            duration_seconds=round(duration, 2),
            timestamp=datetime.now(timezone.utc).isoformat(),
            error=stderr if exit_code != 0 else "",
        )

        result.findings = self._parse_json(stdout)
        result.parsed_data = {"total_findings": len(result.findings)}
        return result

    def _parse_json(self, output: str) -> List[dict]:
        """Parse ffuf JSON output."""
        findings = []
        try:
            data = json.loads(output)
            for r in data.get("results", []):
                findings.append(
                    {
                        "url": r.get("url", ""),
                        "status": r.get("status", 0),
                        "length": r.get("length", 0),
                        "words": r.get("words", 0),
                        "lines": r.get("lines", 0),
                        "input": r.get("input", {}).get("FUZZ", ""),
                        "redirectlocation": r.get("redirectlocation", ""),
                        "content_type": r.get("content-type", ""),
                    }
                )
        except (json.JSONDecodeError, TypeError, AttributeError):
            pass
        return findings


# ---------------------------------------------------------------------------
# Tool Integrator (Facade)
# ---------------------------------------------------------------------------
class ToolIntegrator:
    """Central facade for all external tool integrations."""

    def __init__(self):
        self.nmap = NmapAdapter()
        self.nuclei = NucleiAdapter()
        self.nikto = NiktoAdapter()
        self.whatweb = WhatWebAdapter()
        self.subfinder = SubfinderAdapter()
        self.httpx = HttpxAdapter()
        self.ffuf = FfufAdapter()

        self._adapters = {
            "nmap": self.nmap,
            "nuclei": self.nuclei,
            "nikto": self.nikto,
            "whatweb": self.whatweb,
            "subfinder": self.subfinder,
            "httpx": self.httpx,
            "ffuf": self.ffuf,
        }

    def get_available_tools(self) -> Dict[str, bool]:
        """Return availability status of all supported tools."""
        return {name: adapter.is_available() for name, adapter in self._adapters.items()}

    def run_tool(self, tool_name: str, target: str, **kwargs) -> ToolResult:
        """Run a specific tool by name."""
        adapter = self._adapters.get(tool_name)
        if not adapter:
            return ToolResult(
                tool=tool_name,
                target=target,
                success=False,
                error=f"Unknown tool: {tool_name}",
            )
        result = adapter.run(target, **kwargs)
        # SEC-013: centrally tag simulation-stub output so API consumers
        # can never mistake it for real tool results.
        try:
            from core.tool_runtime import is_simulated_tool

            result.simulated = bool(is_simulated_tool(tool_name))
        except Exception:
            result.simulated = False
        return result

    def run_recon_suite(self, target: str, domain: str = "") -> Dict[str, ToolResult]:
        """Run a full reconnaissance suite with all available tools."""
        results = {}

        if self.whatweb.is_available():
            results["whatweb"] = self.whatweb.run(target)

        if self.httpx.is_available():
            results["httpx"] = self.httpx.run(target)

        if domain and self.subfinder.is_available():
            results["subfinder"] = self.subfinder.run(domain)

        if self.nikto.is_available():
            results["nikto"] = self.nikto.run(target)

        return results

    def run_vuln_scan(self, target: str) -> Dict[str, ToolResult]:
        """Run vulnerability scanning with available tools."""
        results = {}

        if self.nuclei.is_available():
            # Always include built-in templates for automatic scans.
            results["nuclei"] = self.nuclei.run(target, use_builtin=True)

        if self.nmap.is_available():
            from urllib.parse import urlparse

            hostname = urlparse(target).hostname or target
            results["nmap"] = self.nmap.run(hostname, scan_type="vuln")

        return results
