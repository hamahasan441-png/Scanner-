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
  - Httpx      (HTTP probing)

Each tool adapter follows a common interface:
  .is_available() → bool
  .run(target, **opts) → ToolResult
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional


@dataclass
class ToolResult:
    """Standard result from an external tool execution."""
    tool: str
    target: str
    success: bool
    exit_code: int = 0
    raw_output: str = ''
    parsed_data: dict = field(default_factory=dict)
    findings: List[dict] = field(default_factory=list)
    duration_seconds: float = 0.0
    timestamp: str = ''
    error: str = ''

    def to_dict(self) -> dict:
        return {
            'tool': self.tool,
            'target': self.target,
            'success': self.success,
            'exit_code': self.exit_code,
            'findings_count': len(self.findings),
            'findings': self.findings,
            'parsed_data': self.parsed_data,
            'duration_seconds': self.duration_seconds,
            'timestamp': self.timestamp,
            'error': self.error,
        }


def _run_command(cmd: list, timeout: int = 300, cwd: str = None) -> tuple:
    """Safely run a subprocess command with timeout.

    Returns (exit_code, stdout, stderr, duration).
    """
    import time
    start = time.time()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
        duration = time.time() - start
        return result.returncode, result.stdout, result.stderr, duration
    except subprocess.TimeoutExpired:
        duration = time.time() - start
        return -1, '', f'Command timed out after {timeout}s', duration
    except FileNotFoundError:
        return -2, '', f'Command not found: {cmd[0]}', 0.0
    except Exception as e:
        return -3, '', str(e), 0.0


# ---------------------------------------------------------------------------
# Nmap Adapter
# ---------------------------------------------------------------------------
class NmapAdapter:
    """Integration with Nmap network scanner."""

    TOOL_NAME = 'nmap'

    def is_available(self) -> bool:
        return shutil.which('nmap') is not None

    def run(self, target: str, ports: str = '1-1000',
            scan_type: str = 'service', timeout: int = 300) -> ToolResult:
        """Run an Nmap scan.

        Args:
            target: IP address or hostname.
            ports: Port specification (e.g., '80,443' or '1-1000').
            scan_type: 'quick', 'service', 'vuln', or 'full'.
            timeout: Max seconds.
        """
        if not self.is_available():
            return ToolResult(tool=self.TOOL_NAME, target=target, success=False,
                              error='nmap not installed')

        cmd = ['nmap', '-Pn']
        if scan_type == 'quick':
            cmd += ['-F', '-T4']
        elif scan_type == 'service':
            cmd += ['-sV', '-sC', '-p', ports]
        elif scan_type == 'vuln':
            cmd += ['-sV', '--script', 'vuln', '-p', ports]
        elif scan_type == 'full':
            cmd += ['-sV', '-sC', '-O', '-p-', '-T4']
        else:
            cmd += ['-sV', '-p', ports]

        # Use XML output for parsing
        with tempfile.NamedTemporaryFile(suffix='.xml', delete=False) as tmp:
            xml_path = tmp.name
        cmd += ['-oX', xml_path, target]

        exit_code, stdout, stderr, duration = _run_command(cmd, timeout=timeout)

        result = ToolResult(
            tool=self.TOOL_NAME,
            target=target,
            success=exit_code == 0,
            exit_code=exit_code,
            raw_output=stdout,
            duration_seconds=round(duration, 2),
            timestamp=datetime.now(timezone.utc).isoformat(),
            error=stderr if exit_code != 0 else '',
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
        for host_elem in root.findall('.//host'):
            host_data = {'addresses': [], 'ports': [], 'os': []}

            for addr in host_elem.findall('.//address'):
                host_data['addresses'].append({
                    'addr': addr.get('addr', ''),
                    'addrtype': addr.get('addrtype', ''),
                })

            for port in host_elem.findall('.//port'):
                state = port.find('state')
                service = port.find('service')
                port_info = {
                    'port': port.get('portid', ''),
                    'protocol': port.get('protocol', ''),
                    'state': state.get('state', '') if state is not None else '',
                    'service': service.get('name', '') if service is not None else '',
                    'product': service.get('product', '') if service is not None else '',
                    'version': service.get('version', '') if service is not None else '',
                }
                # Check for script output (vuln results)
                scripts = []
                for script in port.findall('.//script'):
                    scripts.append({
                        'id': script.get('id', ''),
                        'output': script.get('output', '')[:500],
                    })
                port_info['scripts'] = scripts
                host_data['ports'].append(port_info)

            hosts.append(host_data)

        return {'hosts': hosts}

    def _extract_findings(self, parsed: dict) -> List[dict]:
        """Extract vulnerability findings from parsed Nmap data."""
        findings = []
        for host in parsed.get('hosts', []):
            addr = host['addresses'][0]['addr'] if host['addresses'] else 'unknown'
            for port in host.get('ports', []):
                if port['state'] == 'open':
                    findings.append({
                        'type': 'open_port',
                        'host': addr,
                        'port': port['port'],
                        'protocol': port['protocol'],
                        'service': port['service'],
                        'product': port['product'],
                        'version': port['version'],
                    })
                for script in port.get('scripts', []):
                    if 'vuln' in script['id'].lower() or 'exploit' in script['output'].lower():
                        findings.append({
                            'type': 'vulnerability',
                            'host': addr,
                            'port': port['port'],
                            'script': script['id'],
                            'details': script['output'][:300],
                        })
        return findings


# ---------------------------------------------------------------------------
# Nuclei Adapter
# ---------------------------------------------------------------------------
class NucleiAdapter:
    """Integration with ProjectDiscovery Nuclei scanner."""

    TOOL_NAME = 'nuclei'

    def is_available(self) -> bool:
        return shutil.which('nuclei') is not None

    def run(self, target: str, templates: str = '', severity: str = '',
            tags: str = '', timeout: int = 600) -> ToolResult:
        """Run a Nuclei scan.

        Args:
            target: URL to scan.
            templates: Template directory or specific template path.
            severity: Filter by severity (critical, high, medium, low, info).
            tags: Filter templates by tags (e.g., 'cve,owasp').
            timeout: Max seconds.
        """
        if not self.is_available():
            return ToolResult(tool=self.TOOL_NAME, target=target, success=False,
                              error='nuclei not installed')

        cmd = ['nuclei', '-u', target, '-jsonl', '-silent']
        if templates:
            cmd += ['-t', templates]
        if severity:
            cmd += ['-severity', severity]
        if tags:
            cmd += ['-tags', tags]

        exit_code, stdout, stderr, duration = _run_command(cmd, timeout=timeout)

        result = ToolResult(
            tool=self.TOOL_NAME,
            target=target,
            success=exit_code == 0,
            exit_code=exit_code,
            raw_output=stdout,
            duration_seconds=round(duration, 2),
            timestamp=datetime.now(timezone.utc).isoformat(),
            error=stderr if exit_code != 0 else '',
        )

        result.findings = self._parse_jsonl(stdout)
        result.parsed_data = {'total_findings': len(result.findings)}
        return result

    def _parse_jsonl(self, output: str) -> List[dict]:
        """Parse Nuclei JSONL output."""
        findings = []
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                findings.append({
                    'template_id': data.get('template-id', ''),
                    'name': data.get('info', {}).get('name', ''),
                    'severity': data.get('info', {}).get('severity', ''),
                    'type': data.get('type', ''),
                    'host': data.get('host', ''),
                    'matched_at': data.get('matched-at', ''),
                    'description': data.get('info', {}).get('description', '')[:300],
                    'reference': data.get('info', {}).get('reference', [])[:5],
                    'tags': data.get('info', {}).get('tags', []),
                })
            except (json.JSONDecodeError, AttributeError):
                continue
        return findings


# ---------------------------------------------------------------------------
# Nikto Adapter
# ---------------------------------------------------------------------------
class NiktoAdapter:
    """Integration with Nikto web server scanner."""

    TOOL_NAME = 'nikto'

    def is_available(self) -> bool:
        return shutil.which('nikto') is not None

    def run(self, target: str, tuning: str = '', timeout: int = 300) -> ToolResult:
        """Run a Nikto scan.

        Args:
            target: URL to scan.
            tuning: Scan tuning options (e.g., '123bde' for specific test types).
            timeout: Max seconds.
        """
        if not self.is_available():
            return ToolResult(tool=self.TOOL_NAME, target=target, success=False,
                              error='nikto not installed')

        cmd = ['nikto', '-h', target, '-Format', 'json', '-o', '-']
        if tuning:
            cmd += ['-Tuning', tuning]

        exit_code, stdout, stderr, duration = _run_command(cmd, timeout=timeout)

        result = ToolResult(
            tool=self.TOOL_NAME,
            target=target,
            success=exit_code == 0,
            exit_code=exit_code,
            raw_output=stdout,
            duration_seconds=round(duration, 2),
            timestamp=datetime.now(timezone.utc).isoformat(),
            error=stderr if exit_code != 0 else '',
        )

        result.findings = self._parse_output(stdout)
        result.parsed_data = {'total_findings': len(result.findings)}
        return result

    def _parse_output(self, output: str) -> List[dict]:
        """Parse Nikto JSON output."""
        findings = []
        try:
            data = json.loads(output)
            if isinstance(data, dict):
                vulns = data.get('vulnerabilities', [])
                for v in vulns:
                    findings.append({
                        'id': v.get('id', ''),
                        'method': v.get('method', ''),
                        'url': v.get('url', ''),
                        'msg': v.get('msg', ''),
                        'references': v.get('references', {}),
                    })
        except (json.JSONDecodeError, TypeError):
            # Fallback: parse text output
            for line in output.split('\n'):
                line = line.strip()
                if line.startswith('+') and ': ' in line:
                    findings.append({'msg': line[2:], 'type': 'nikto_finding'})
        return findings


# ---------------------------------------------------------------------------
# WhatWeb Adapter
# ---------------------------------------------------------------------------
class WhatWebAdapter:
    """Integration with WhatWeb technology fingerprinting."""

    TOOL_NAME = 'whatweb'

    def is_available(self) -> bool:
        return shutil.which('whatweb') is not None

    def run(self, target: str, aggression: int = 1, timeout: int = 120) -> ToolResult:
        """Run WhatWeb fingerprinting.

        Args:
            target: URL to fingerprint.
            aggression: Aggression level (1=stealthy, 3=aggressive).
            timeout: Max seconds.
        """
        if not self.is_available():
            return ToolResult(tool=self.TOOL_NAME, target=target, success=False,
                              error='whatweb not installed')

        cmd = ['whatweb', '--log-json=-', f'-a{aggression}', target]

        exit_code, stdout, stderr, duration = _run_command(cmd, timeout=timeout)

        result = ToolResult(
            tool=self.TOOL_NAME,
            target=target,
            success=exit_code == 0,
            exit_code=exit_code,
            raw_output=stdout,
            duration_seconds=round(duration, 2),
            timestamp=datetime.now(timezone.utc).isoformat(),
            error=stderr if exit_code != 0 else '',
        )

        result.parsed_data = self._parse_json(stdout)
        result.findings = self._extract_technologies(result.parsed_data)
        return result

    def _parse_json(self, output: str) -> dict:
        """Parse WhatWeb JSON output."""
        technologies = []
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                technologies.append(data)
            except json.JSONDecodeError:
                continue
        return {'entries': technologies}

    def _extract_technologies(self, parsed: dict) -> List[dict]:
        """Extract technology findings."""
        findings = []
        for entry in parsed.get('entries', []):
            plugins = entry.get('plugins', {})
            for name, info in plugins.items():
                finding = {
                    'technology': name,
                    'version': '',
                    'string': [],
                }
                if isinstance(info, dict):
                    finding['version'] = info.get('version', [''])[0] if info.get('version') else ''
                    finding['string'] = info.get('string', [])[:3]
                findings.append(finding)
        return findings


# ---------------------------------------------------------------------------
# Subfinder Adapter
# ---------------------------------------------------------------------------
class SubfinderAdapter:
    """Integration with ProjectDiscovery Subfinder for subdomain enumeration."""

    TOOL_NAME = 'subfinder'

    def is_available(self) -> bool:
        return shutil.which('subfinder') is not None

    def run(self, domain: str, timeout: int = 120) -> ToolResult:
        """Run subdomain enumeration.

        Args:
            domain: Domain to enumerate subdomains for.
            timeout: Max seconds.
        """
        if not self.is_available():
            return ToolResult(tool=self.TOOL_NAME, target=domain, success=False,
                              error='subfinder not installed')

        cmd = ['subfinder', '-d', domain, '-silent']

        exit_code, stdout, stderr, duration = _run_command(cmd, timeout=timeout)

        result = ToolResult(
            tool=self.TOOL_NAME,
            target=domain,
            success=exit_code == 0,
            exit_code=exit_code,
            raw_output=stdout,
            duration_seconds=round(duration, 2),
            timestamp=datetime.now(timezone.utc).isoformat(),
            error=stderr if exit_code != 0 else '',
        )

        subdomains = [s.strip() for s in stdout.strip().split('\n') if s.strip()]
        result.findings = [{'subdomain': s} for s in subdomains]
        result.parsed_data = {'total_subdomains': len(subdomains), 'subdomains': subdomains}
        return result


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

        self._adapters = {
            'nmap': self.nmap,
            'nuclei': self.nuclei,
            'nikto': self.nikto,
            'whatweb': self.whatweb,
            'subfinder': self.subfinder,
        }

    def get_available_tools(self) -> Dict[str, bool]:
        """Return availability status of all supported tools."""
        return {name: adapter.is_available() for name, adapter in self._adapters.items()}

    def run_tool(self, tool_name: str, target: str, **kwargs) -> ToolResult:
        """Run a specific tool by name."""
        adapter = self._adapters.get(tool_name)
        if not adapter:
            return ToolResult(
                tool=tool_name, target=target, success=False,
                error=f'Unknown tool: {tool_name}',
            )
        return adapter.run(target, **kwargs)

    def run_recon_suite(self, target: str, domain: str = '') -> Dict[str, ToolResult]:
        """Run a full reconnaissance suite with all available tools."""
        results = {}

        if self.whatweb.is_available():
            results['whatweb'] = self.whatweb.run(target)

        if domain and self.subfinder.is_available():
            results['subfinder'] = self.subfinder.run(domain)

        if self.nikto.is_available():
            results['nikto'] = self.nikto.run(target)

        return results

    def run_vuln_scan(self, target: str) -> Dict[str, ToolResult]:
        """Run vulnerability scanning with available tools."""
        results = {}

        if self.nuclei.is_available():
            results['nuclei'] = self.nuclei.run(target)

        if self.nmap.is_available():
            from urllib.parse import urlparse
            hostname = urlparse(target).hostname or target
            results['nmap'] = self.nmap.run(hostname, scan_type='vuln')

        return results
