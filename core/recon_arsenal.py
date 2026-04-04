#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Recon Arsenal: Advanced Discovery & Gathering Tools
Integrates the best-in-class GitHub security reconnaissance tools:

  Subdomain & DNS:
    - Amass       (OWASP advanced subdomain enumeration & network mapping)
    - dnsx        (ProjectDiscovery fast multi-purpose DNS toolkit)

  HTTP Probing & Crawling:
    - httpx       (ProjectDiscovery fast HTTP probing & tech detection)
    - katana      (ProjectDiscovery next-gen web crawler)
    - hakrawler   (Fast web crawler for URL/JS endpoint discovery)

  URL & Parameter Gathering:
    - gau         (Get All URLs from Wayback, CommonCrawl, OTX, URLScan)
    - waybackurls (Fetch known URLs from Wayback Machine)
    - ParamSpider (Mining URLs with parameters from web archives)
    - Arjun       (HTTP parameter discovery suite)

  Directory & Content Discovery:
    - ffuf        (Fast web fuzzer for directory/vhost/parameter bruteforcing)
    - gobuster    (Directory/DNS/vhost brute-forcing)
    - feroxbuster (Recursive content discovery in Rust)
    - dirsearch   (Web path scanner with smart wordlist)

  Port Scanning:
    - masscan     (Fastest Internet port scanner)
    - rustscan    (Fast port scanner that pipes into Nmap)

Each adapter follows the standard ToolResult interface:
  .is_available() -> bool
  .run(target, **opts) -> ToolResult
"""

import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from typing import Dict, List, Optional

from core.tool_integrator import ToolResult, _run_command


# ---------------------------------------------------------------------------
# Amass Adapter — OWASP Advanced Subdomain Enumeration
# ---------------------------------------------------------------------------
class AmassAdapter:
    """Integration with OWASP Amass for advanced subdomain enumeration.

    GitHub: https://github.com/owasp-amass/amass
    Performs passive and active subdomain enumeration with DNS resolution,
    ASN discovery, certificate transparency, and network mapping.
    """

    TOOL_NAME = 'amass'

    def is_available(self) -> bool:
        return shutil.which('amass') is not None

    def run(self, domain: str, mode: str = 'passive',
            timeout: int = 600) -> ToolResult:
        """Run Amass subdomain enumeration.

        Args:
            domain: Target domain to enumerate.
            mode: 'passive' (safe, no direct queries) or 'active'.
            timeout: Max seconds (default 600 for thorough enum).
        """
        if not self.is_available():
            return ToolResult(tool=self.TOOL_NAME, target=domain, success=False,
                              error='amass not installed')

        with tempfile.NamedTemporaryFile(suffix='.json', delete=False,
                                         mode='w') as tmp:
            json_path = tmp.name

        cmd = ['amass', 'enum', '-d', domain, '-json', json_path]
        if mode == 'passive':
            cmd.append('-passive')
        elif mode == 'active':
            cmd.append('-active')

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

        try:
            if os.path.isfile(json_path):
                result.parsed_data, result.findings = self._parse_json(json_path)
        finally:
            if os.path.isfile(json_path):
                os.unlink(json_path)

        return result

    def _parse_json(self, json_path: str) -> tuple:
        """Parse Amass JSON Lines output."""
        subdomains = set()
        addresses = set()
        findings = []

        try:
            with open(json_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        name = entry.get('name', '')
                        if name:
                            subdomains.add(name)
                        for addr in entry.get('addresses', []):
                            ip = addr.get('ip', '')
                            if ip:
                                addresses.add(ip)
                            findings.append({
                                'subdomain': name,
                                'ip': ip,
                                'cidr': addr.get('cidr', ''),
                                'asn': addr.get('asn', 0),
                                'desc': addr.get('desc', ''),
                            })
                    except json.JSONDecodeError:
                        continue
        except (IOError, OSError):
            pass

        parsed = {
            'total_subdomains': len(subdomains),
            'total_addresses': len(addresses),
            'subdomains': sorted(subdomains),
            'addresses': sorted(addresses),
        }
        return parsed, findings


# ---------------------------------------------------------------------------
# httpx Adapter — Fast HTTP Probing & Tech Detection
# ---------------------------------------------------------------------------
class HttpxAdapter:
    """Integration with ProjectDiscovery httpx for HTTP probing.

    GitHub: https://github.com/projectdiscovery/httpx
    Probes discovered hosts for live HTTP services, extracts titles,
    status codes, technologies, content length, and more.
    """

    TOOL_NAME = 'httpx'

    def is_available(self) -> bool:
        return shutil.which('httpx') is not None

    def run(self, target: str, input_list: str = '',
            tech_detect: bool = True, timeout: int = 300) -> ToolResult:
        """Run httpx HTTP probing.

        Args:
            target: Single URL/host or domain to probe.
            input_list: Path to file with list of hosts (one per line).
            tech_detect: Enable technology detection.
            timeout: Max seconds.
        """
        if not self.is_available():
            return ToolResult(tool=self.TOOL_NAME, target=target, success=False,
                              error='httpx not installed')

        cmd = ['httpx', '-silent', '-json',
               '-status-code', '-title', '-content-length',
               '-web-server', '-follow-redirects']

        if tech_detect:
            cmd.append('-tech-detect')

        if input_list and os.path.isfile(input_list):
            cmd += ['-l', input_list]
        else:
            cmd += ['-u', target]

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
        result.parsed_data = {
            'total_hosts': len(result.findings),
            'live_hosts': [f.get('url', '') for f in result.findings],
        }
        return result

    def _parse_jsonl(self, output: str) -> List[dict]:
        """Parse httpx JSON Lines output."""
        findings = []
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                findings.append({
                    'url': data.get('url', ''),
                    'status_code': data.get('status_code', 0),
                    'title': data.get('title', ''),
                    'content_length': data.get('content_length', 0),
                    'web_server': data.get('webserver', ''),
                    'technologies': data.get('tech', []),
                    'host': data.get('host', ''),
                    'scheme': data.get('scheme', ''),
                    'content_type': data.get('content_type', ''),
                })
            except (json.JSONDecodeError, AttributeError):
                continue
        return findings


# ---------------------------------------------------------------------------
# Katana Adapter — Next-Gen Web Crawler
# ---------------------------------------------------------------------------
class KatanaAdapter:
    """Integration with ProjectDiscovery Katana for web crawling.

    GitHub: https://github.com/projectdiscovery/katana
    Fast and configurable web crawler with automatic form filling,
    scope control, and JavaScript rendering support.
    """

    TOOL_NAME = 'katana'

    def is_available(self) -> bool:
        return shutil.which('katana') is not None

    def run(self, target: str, depth: int = 3, js_crawl: bool = False,
            timeout: int = 300) -> ToolResult:
        """Run Katana web crawler.

        Args:
            target: URL to crawl.
            depth: Maximum crawl depth (default: 3).
            js_crawl: Enable headless browser for JavaScript rendering.
            timeout: Max seconds.
        """
        if not self.is_available():
            return ToolResult(tool=self.TOOL_NAME, target=target, success=False,
                              error='katana not installed')

        cmd = ['katana', '-u', target, '-silent', '-jsonl',
               '-d', str(depth)]
        if js_crawl:
            cmd += ['-headless']

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
        urls = [f.get('url', '') for f in result.findings]
        result.parsed_data = {
            'total_urls': len(urls),
            'urls': urls,
            'endpoints': [u for u in urls if '?' in u],
        }
        return result

    def _parse_output(self, output: str) -> List[dict]:
        """Parse Katana JSONL or plain output."""
        findings = []
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                findings.append({
                    'url': data.get('request', {}).get('endpoint', line.strip()),
                    'method': data.get('request', {}).get('method', 'GET'),
                    'source': data.get('request', {}).get('source', ''),
                    'tag': data.get('request', {}).get('tag', ''),
                    'attribute': data.get('request', {}).get('attribute', ''),
                })
            except (json.JSONDecodeError, AttributeError):
                url = line.strip()
                if url.startswith('http'):
                    findings.append({'url': url, 'method': 'GET',
                                     'source': '', 'tag': '', 'attribute': ''})
        return findings


# ---------------------------------------------------------------------------
# dnsx Adapter — Fast DNS Toolkit
# ---------------------------------------------------------------------------
class DnsxAdapter:
    """Integration with ProjectDiscovery dnsx for DNS resolution.

    GitHub: https://github.com/projectdiscovery/dnsx
    Fast DNS toolkit that supports multiple query types,
    wildcard filtering, and bulk resolution.
    """

    TOOL_NAME = 'dnsx'

    def is_available(self) -> bool:
        return shutil.which('dnsx') is not None

    def run(self, domain: str, wordlist: str = '', record_types: str = 'a,aaaa,cname,mx,ns,txt',
            timeout: int = 120) -> ToolResult:
        """Run dnsx DNS resolution/bruteforce.

        Args:
            domain: Target domain.
            wordlist: Optional subdomain wordlist for brute-force.
            record_types: Comma-separated DNS record types.
            timeout: Max seconds.
        """
        if not self.is_available():
            return ToolResult(tool=self.TOOL_NAME, target=domain, success=False,
                              error='dnsx not installed')

        cmd = ['dnsx', '-silent', '-json', '-resp']

        for rtype in record_types.split(','):
            rtype = rtype.strip().lower()
            if rtype in ('a', 'aaaa', 'cname', 'mx', 'ns', 'txt', 'soa', 'ptr'):
                cmd.append(f'-{rtype}')

        if wordlist and os.path.isfile(wordlist):
            cmd += ['-w', wordlist, '-d', domain]
        else:
            cmd += ['-d', domain]

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

        result.findings = self._parse_jsonl(stdout)
        result.parsed_data = {'total_records': len(result.findings)}
        return result

    def _parse_jsonl(self, output: str) -> List[dict]:
        """Parse dnsx JSON output."""
        findings = []
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                findings.append({
                    'host': data.get('host', ''),
                    'resolver': data.get('resolver', []),
                    'a': data.get('a', []),
                    'aaaa': data.get('aaaa', []),
                    'cname': data.get('cname', []),
                    'mx': data.get('mx', []),
                    'ns': data.get('ns', []),
                    'txt': data.get('txt', []),
                    'soa': data.get('soa', []),
                    'status_code': data.get('status_code', ''),
                })
            except (json.JSONDecodeError, AttributeError):
                continue
        return findings


# ---------------------------------------------------------------------------
# ffuf Adapter — Fast Web Fuzzer
# ---------------------------------------------------------------------------
class FfufAdapter:
    """Integration with ffuf for web fuzzing / directory discovery.

    GitHub: https://github.com/ffuf/ffuf
    Fast web fuzzer supporting directory discovery, vhost brute-forcing,
    parameter fuzzing with flexible filtering.
    """

    TOOL_NAME = 'ffuf'

    def is_available(self) -> bool:
        return shutil.which('ffuf') is not None

    def run(self, target: str, wordlist: str = '', mode: str = 'dir',
            extensions: str = '', filter_code: str = '404',
            timeout: int = 300) -> ToolResult:
        """Run ffuf fuzzer.

        Args:
            target: Base URL (use FUZZ keyword for fuzzing position).
            wordlist: Path to wordlist file.
            mode: 'dir' (directory), 'vhost' (virtual host), 'param' (parameter).
            extensions: File extensions to append (e.g., 'php,html,js').
            filter_code: HTTP status codes to filter out (e.g., '404,403').
            timeout: Max seconds.
        """
        if not self.is_available():
            return ToolResult(tool=self.TOOL_NAME, target=target, success=False,
                              error='ffuf not installed')

        # Auto-add FUZZ keyword for directory mode
        url = target
        if mode == 'dir' and 'FUZZ' not in target:
            url = target.rstrip('/') + '/FUZZ'
        elif mode == 'vhost' and 'FUZZ' not in target:
            url = target

        cmd = ['ffuf', '-u', url, '-o', '/dev/stdout', '-of', 'json', '-silent']

        if wordlist and os.path.isfile(wordlist):
            cmd += ['-w', wordlist]
        else:
            cmd += ['-w', '-']  # stdin

        if extensions and mode == 'dir':
            cmd += ['-e', extensions]

        if filter_code:
            cmd += ['-fc', filter_code]

        if mode == 'vhost':
            cmd += ['-H', 'Host: FUZZ.' + target.split('//')[1].split('/')[0] if '//' in target else target]

        exit_code, stdout, stderr, duration = _run_command(cmd, timeout=timeout)

        result = ToolResult(
            tool=self.TOOL_NAME,
            target=target,
            success=exit_code in (0, 1),  # ffuf returns 1 when no matches
            exit_code=exit_code,
            raw_output=stdout,
            duration_seconds=round(duration, 2),
            timestamp=datetime.now(timezone.utc).isoformat(),
            error=stderr if exit_code not in (0, 1) else '',
        )

        result.findings = self._parse_json(stdout)
        result.parsed_data = {
            'total_results': len(result.findings),
            'mode': mode,
        }
        return result

    def _parse_json(self, output: str) -> List[dict]:
        """Parse ffuf JSON output."""
        findings = []
        try:
            data = json.loads(output)
            for entry in data.get('results', []):
                findings.append({
                    'url': entry.get('url', ''),
                    'status': entry.get('status', 0),
                    'length': entry.get('length', 0),
                    'words': entry.get('words', 0),
                    'lines': entry.get('lines', 0),
                    'input': entry.get('input', {}).get('FUZZ', ''),
                    'content_type': entry.get('content-type', ''),
                    'redirect_location': entry.get('redirectlocation', ''),
                })
        except (json.JSONDecodeError, TypeError):
            pass
        return findings


# ---------------------------------------------------------------------------
# gau Adapter — Get All URLs
# ---------------------------------------------------------------------------
class GauAdapter:
    """Integration with gau (Get All URLs) for URL harvesting.

    GitHub: https://github.com/lc/gau
    Fetches known URLs from AlienVault OTX, Wayback Machine,
    Common Crawl, and URLScan.
    """

    TOOL_NAME = 'gau'

    def is_available(self) -> bool:
        return shutil.which('gau') is not None

    def run(self, domain: str, providers: str = '',
            blacklist: str = 'png,jpg,gif,css,woff,svg,ico',
            timeout: int = 120) -> ToolResult:
        """Run gau URL harvesting.

        Args:
            domain: Target domain.
            providers: Comma-separated providers (wayback,commoncrawl,otx,urlscan).
            blacklist: File extensions to exclude.
            timeout: Max seconds.
        """
        if not self.is_available():
            return ToolResult(tool=self.TOOL_NAME, target=domain, success=False,
                              error='gau not installed')

        cmd = ['gau', '--subs', domain]
        if providers:
            cmd += ['--providers', providers]
        if blacklist:
            cmd += ['--blacklist', blacklist]

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

        urls = sorted(set(u.strip() for u in stdout.strip().split('\n') if u.strip()))
        param_urls = [u for u in urls if '?' in u]
        result.findings = [{'url': u, 'has_params': '?' in u} for u in urls]
        result.parsed_data = {
            'total_urls': len(urls),
            'urls_with_params': len(param_urls),
            'unique_params': self._extract_params(param_urls),
        }
        return result

    def _extract_params(self, urls: List[str]) -> List[str]:
        """Extract unique parameter names from URLs."""
        params = set()
        for url in urls:
            if '?' in url:
                query = url.split('?', 1)[1]
                for pair in query.split('&'):
                    name = pair.split('=', 1)[0]
                    if name:
                        params.add(name)
        return sorted(params)


# ---------------------------------------------------------------------------
# waybackurls Adapter — Wayback Machine URL Fetcher
# ---------------------------------------------------------------------------
class WaybackurlsAdapter:
    """Integration with waybackurls for Wayback Machine URL harvesting.

    GitHub: https://github.com/tomnomnom/waybackurls
    Fetches all known URLs for a domain from the Wayback Machine.
    """

    TOOL_NAME = 'waybackurls'

    def is_available(self) -> bool:
        return shutil.which('waybackurls') is not None

    def run(self, domain: str, no_subs: bool = False,
            timeout: int = 120) -> ToolResult:
        """Run waybackurls.

        Args:
            domain: Target domain.
            no_subs: If True, exclude subdomains from results.
            timeout: Max seconds.
        """
        if not self.is_available():
            return ToolResult(tool=self.TOOL_NAME, target=domain, success=False,
                              error='waybackurls not installed')

        cmd = ['waybackurls', domain]
        if no_subs:
            cmd.append('-no-subs')

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

        urls = sorted(set(u.strip() for u in stdout.strip().split('\n') if u.strip()))
        result.findings = [{'url': u} for u in urls]
        result.parsed_data = {
            'total_urls': len(urls),
            'urls_with_params': len([u for u in urls if '?' in u]),
        }
        return result


# ---------------------------------------------------------------------------
# Gobuster Adapter — Directory/DNS/VHost Brute-Forcing
# ---------------------------------------------------------------------------
class GobusterAdapter:
    """Integration with Gobuster for directory/DNS/vhost brute-forcing.

    GitHub: https://github.com/OJ/gobuster
    Fast brute-force tool for discovering directories, subdomains,
    virtual hosts, S3 buckets, and TFTP servers.
    """

    TOOL_NAME = 'gobuster'

    def is_available(self) -> bool:
        return shutil.which('gobuster') is not None

    def run(self, target: str, mode: str = 'dir', wordlist: str = '',
            extensions: str = '', timeout: int = 300) -> ToolResult:
        """Run Gobuster.

        Args:
            target: URL for dir mode, domain for dns mode.
            mode: 'dir' (directory), 'dns' (subdomain), 'vhost'.
            wordlist: Path to wordlist file.
            extensions: File extensions for dir mode (e.g., 'php,html,txt').
            timeout: Max seconds.
        """
        if not self.is_available():
            return ToolResult(tool=self.TOOL_NAME, target=target, success=False,
                              error='gobuster not installed')

        cmd = ['gobuster', mode, '-q', '--no-color']

        if mode == 'dir':
            cmd += ['-u', target]
        elif mode == 'dns':
            cmd += ['-d', target]
        elif mode == 'vhost':
            cmd += ['-u', target]

        if wordlist and os.path.isfile(wordlist):
            cmd += ['-w', wordlist]

        if extensions and mode == 'dir':
            cmd += ['-x', extensions]

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

        result.findings = self._parse_output(stdout, mode)
        result.parsed_data = {
            'total_results': len(result.findings),
            'mode': mode,
        }
        return result

    def _parse_output(self, output: str, mode: str) -> List[dict]:
        """Parse Gobuster output."""
        findings = []
        for line in output.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith('='):
                continue
            if mode == 'dir':
                # Format: /path (Status: 200) [Size: 1234]
                parts = line.split()
                if parts:
                    finding = {'path': parts[0], 'status': 0, 'size': 0}
                    for i, p in enumerate(parts):
                        if p == '(Status:' and i + 1 < len(parts):
                            try:
                                finding['status'] = int(parts[i + 1].rstrip(')'))
                            except ValueError:
                                pass
                        if p == '[Size:' and i + 1 < len(parts):
                            try:
                                finding['size'] = int(parts[i + 1].rstrip(']'))
                            except ValueError:
                                pass
                    findings.append(finding)
            elif mode == 'dns':
                # Format: Found: subdomain.example.com
                if line.startswith('Found:'):
                    sub = line.replace('Found:', '').strip()
                    findings.append({'subdomain': sub})
                elif '.' in line:
                    findings.append({'subdomain': line})
            elif mode == 'vhost':
                if 'Found:' in line:
                    vhost = line.split('Found:')[1].strip().split()[0]
                    findings.append({'vhost': vhost})
        return findings


# ---------------------------------------------------------------------------
# Feroxbuster Adapter — Recursive Content Discovery
# ---------------------------------------------------------------------------
class FeroxbusterAdapter:
    """Integration with Feroxbuster for recursive content discovery.

    GitHub: https://github.com/epi052/feroxbuster
    Fast, recursive content discovery written in Rust with
    auto-filtering, smart recursion, and JSON output.
    """

    TOOL_NAME = 'feroxbuster'

    def is_available(self) -> bool:
        return shutil.which('feroxbuster') is not None

    def run(self, target: str, wordlist: str = '', depth: int = 2,
            extensions: str = '', filter_code: str = '404',
            timeout: int = 300) -> ToolResult:
        """Run Feroxbuster recursive discovery.

        Args:
            target: URL to scan.
            wordlist: Path to wordlist.
            depth: Recursion depth (default: 2).
            extensions: File extensions (e.g., 'php,html,js').
            filter_code: Status codes to filter.
            timeout: Max seconds.
        """
        if not self.is_available():
            return ToolResult(tool=self.TOOL_NAME, target=target, success=False,
                              error='feroxbuster not installed')

        cmd = ['feroxbuster', '-u', target, '--silent', '--json',
               '-d', str(depth), '--no-state']

        if wordlist and os.path.isfile(wordlist):
            cmd += ['-w', wordlist]

        if extensions:
            cmd += ['-x', extensions]

        if filter_code:
            for code in filter_code.split(','):
                cmd += ['-C', code.strip()]

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
        result.parsed_data = {'total_results': len(result.findings)}
        return result

    def _parse_jsonl(self, output: str) -> List[dict]:
        """Parse Feroxbuster JSON Lines output."""
        findings = []
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                if data.get('type') == 'response':
                    findings.append({
                        'url': data.get('url', ''),
                        'status': data.get('status', 0),
                        'content_length': data.get('content_length', 0),
                        'lines': data.get('line_count', 0),
                        'words': data.get('word_count', 0),
                        'method': data.get('method', 'GET'),
                    })
            except (json.JSONDecodeError, AttributeError):
                continue
        return findings


# ---------------------------------------------------------------------------
# Masscan Adapter — Fastest Internet Port Scanner
# ---------------------------------------------------------------------------
class MasscanAdapter:
    """Integration with Masscan for ultra-fast port scanning.

    GitHub: https://github.com/robertdavidgraham/masscan
    The fastest Internet port scanner — can scan the entire Internet
    in under 6 minutes at 10M pps. Uses custom TCP/IP stack.
    """

    TOOL_NAME = 'masscan'

    def is_available(self) -> bool:
        return shutil.which('masscan') is not None

    def run(self, target: str, ports: str = '1-65535',
            rate: int = 1000, timeout: int = 300) -> ToolResult:
        """Run Masscan port scanning.

        Args:
            target: IP address, CIDR range, or hostname.
            ports: Port specification (e.g., '80,443' or '1-65535').
            rate: Packets per second (default: 1000).
            timeout: Max seconds.
        """
        if not self.is_available():
            return ToolResult(tool=self.TOOL_NAME, target=target, success=False,
                              error='masscan not installed')

        with tempfile.NamedTemporaryFile(suffix='.json', delete=False,
                                         mode='w') as tmp:
            json_path = tmp.name

        cmd = ['masscan', target, '-p', ports,
               '--rate', str(rate), '-oJ', json_path]

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

        try:
            if os.path.isfile(json_path):
                result.findings = self._parse_json(json_path)
                result.parsed_data = {
                    'total_open_ports': len(result.findings),
                    'unique_ips': list(set(f.get('ip', '') for f in result.findings)),
                }
        finally:
            if os.path.isfile(json_path):
                os.unlink(json_path)

        return result

    def _parse_json(self, json_path: str) -> List[dict]:
        """Parse Masscan JSON output."""
        findings = []
        try:
            with open(json_path, 'r') as f:
                content = f.read().strip()
                # Masscan JSON can have trailing comma issues
                if content.endswith(','):
                    content = content[:-1]
                if not content.startswith('['):
                    content = '[' + content
                if not content.endswith(']'):
                    content = content + ']'
                data = json.loads(content)
                for entry in data:
                    ip = entry.get('ip', '')
                    for port_info in entry.get('ports', []):
                        findings.append({
                            'ip': ip,
                            'port': port_info.get('port', 0),
                            'protocol': port_info.get('proto', 'tcp'),
                            'status': port_info.get('status', 'open'),
                            'ttl': port_info.get('ttl', 0),
                        })
        except (json.JSONDecodeError, IOError, OSError):
            pass
        return findings


# ---------------------------------------------------------------------------
# Rustscan Adapter — Fast Port Scanner
# ---------------------------------------------------------------------------
class RustscanAdapter:
    """Integration with RustScan for fast port scanning.

    GitHub: https://github.com/RustScan/RustScan
    Extremely fast port scanner that can scan all 65535 ports in
    seconds, then pipes results to Nmap for service detection.
    """

    TOOL_NAME = 'rustscan'

    def is_available(self) -> bool:
        return shutil.which('rustscan') is not None

    def run(self, target: str, ports: str = '',
            batch_size: int = 4500, timeout: int = 300) -> ToolResult:
        """Run RustScan port scanning.

        Args:
            target: IP address or hostname.
            ports: Port range (empty for all ports).
            batch_size: Batch size for port scanning.
            timeout: Max seconds.
        """
        if not self.is_available():
            return ToolResult(tool=self.TOOL_NAME, target=target, success=False,
                              error='rustscan not installed')

        cmd = ['rustscan', '-a', target, '-b', str(batch_size), '--greppable']
        if ports:
            cmd += ['-p', ports]

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

        result.findings = self._parse_output(stdout, target)
        result.parsed_data = {
            'total_open_ports': len(result.findings),
            'open_ports': [f['port'] for f in result.findings],
        }
        return result

    def _parse_output(self, output: str, target: str) -> List[dict]:
        """Parse RustScan greppable output."""
        import re
        findings = []
        for line in output.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            # RustScan greppable: "Open <ip>:<port>"
            match = re.match(r'Open\s+(\S+):(\d+)', line)
            if match:
                findings.append({
                    'ip': match.group(1),
                    'port': int(match.group(2)),
                    'protocol': 'tcp',
                    'status': 'open',
                })
            # Also try: port numbers after "->  "
            if '->' in line:
                port_part = line.split('->')[-1].strip()
                for port_str in port_part.split(','):
                    port_str = port_str.strip()
                    if port_str.isdigit():
                        findings.append({
                            'ip': target,
                            'port': int(port_str),
                            'protocol': 'tcp',
                            'status': 'open',
                        })
        return findings


# ---------------------------------------------------------------------------
# Hakrawler Adapter — Web Crawler for URL/JS Discovery
# ---------------------------------------------------------------------------
class HakrawlerAdapter:
    """Integration with Hakrawler for web crawling.

    GitHub: https://github.com/hakluke/hakrawler
    Fast web crawler extracting URLs, JavaScript files,
    and form action endpoints from web pages.
    """

    TOOL_NAME = 'hakrawler'

    def is_available(self) -> bool:
        return shutil.which('hakrawler') is not None

    def run(self, target: str, depth: int = 2, scope: str = 'subs',
            timeout: int = 120) -> ToolResult:
        """Run Hakrawler.

        Args:
            target: URL to crawl.
            depth: Crawl depth.
            scope: 'strict' (same host), 'subs' (include subdomains), 'fuzzy'.
            timeout: Max seconds.
        """
        if not self.is_available():
            return ToolResult(tool=self.TOOL_NAME, target=target, success=False,
                              error='hakrawler not installed')

        cmd = ['hakrawler', '-url', target, '-depth', str(depth),
               '-scope', scope, '-plain']

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

        urls = sorted(set(u.strip() for u in stdout.strip().split('\n')
                          if u.strip() and u.strip().startswith('http')))
        js_files = [u for u in urls if u.endswith('.js')]
        result.findings = [{'url': u, 'is_js': u.endswith('.js')} for u in urls]
        result.parsed_data = {
            'total_urls': len(urls),
            'js_files': len(js_files),
            'urls': urls,
        }
        return result


# ---------------------------------------------------------------------------
# Arjun Adapter — HTTP Parameter Discovery
# ---------------------------------------------------------------------------
class ArjunAdapter:
    """Integration with Arjun for HTTP parameter discovery.

    GitHub: https://github.com/s0md3v/Arjun
    Discovers hidden HTTP parameters using intelligent brute-forcing
    and heuristic analysis. Supports GET, POST, JSON, and XML.
    """

    TOOL_NAME = 'arjun'

    def is_available(self) -> bool:
        return shutil.which('arjun') is not None

    def run(self, target: str, method: str = 'GET',
            timeout: int = 300) -> ToolResult:
        """Run Arjun parameter discovery.

        Args:
            target: URL to discover parameters for.
            method: HTTP method (GET, POST, JSON, XML).
            timeout: Max seconds.
        """
        if not self.is_available():
            return ToolResult(tool=self.TOOL_NAME, target=target, success=False,
                              error='arjun not installed')

        with tempfile.NamedTemporaryFile(suffix='.json', delete=False,
                                         mode='w') as tmp:
            json_path = tmp.name

        cmd = ['arjun', '-u', target, '-m', method.upper(),
               '-oJ', json_path]

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

        try:
            if os.path.isfile(json_path):
                result.findings = self._parse_json(json_path)
                result.parsed_data = {
                    'total_params': len(result.findings),
                    'params': [f['name'] for f in result.findings],
                    'method': method.upper(),
                }
        finally:
            if os.path.isfile(json_path):
                os.unlink(json_path)

        return result

    def _parse_json(self, json_path: str) -> List[dict]:
        """Parse Arjun JSON output."""
        findings = []
        try:
            with open(json_path, 'r') as f:
                data = json.load(f)
                if isinstance(data, dict):
                    for url, params in data.items():
                        if isinstance(params, list):
                            for param in params:
                                findings.append({
                                    'url': url,
                                    'name': param if isinstance(param, str)
                                           else param.get('name', ''),
                                    'method': param.get('method', 'GET')
                                             if isinstance(param, dict) else 'GET',
                                })
                        elif isinstance(params, dict):
                            for name, info in params.items():
                                findings.append({
                                    'url': url,
                                    'name': name,
                                    'method': info.get('method', 'GET')
                                             if isinstance(info, dict) else 'GET',
                                })
        except (json.JSONDecodeError, IOError, OSError):
            pass
        return findings


# ---------------------------------------------------------------------------
# ParamSpider Adapter — Parameter Mining from Web Archives
# ---------------------------------------------------------------------------
class ParamSpiderAdapter:
    """Integration with ParamSpider for parameter mining.

    GitHub: https://github.com/devanshbatham/ParamSpider
    Mines parameters from web archives for a given domain,
    useful for finding hidden/undocumented parameters.
    """

    TOOL_NAME = 'paramspider'

    def is_available(self) -> bool:
        return shutil.which('paramspider') is not None

    def run(self, domain: str, exclude: str = 'png,jpg,gif,css,js,woff,svg',
            timeout: int = 120) -> ToolResult:
        """Run ParamSpider.

        Args:
            domain: Target domain.
            exclude: File extensions to exclude.
            timeout: Max seconds.
        """
        if not self.is_available():
            return ToolResult(tool=self.TOOL_NAME, target=domain, success=False,
                              error='paramspider not installed')

        cmd = ['paramspider', '-d', domain]
        if exclude:
            cmd += ['--exclude', exclude]

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

        urls = sorted(set(u.strip() for u in stdout.strip().split('\n')
                          if u.strip() and ('http' in u or 'FUZZ' in u)))
        params = set()
        for u in urls:
            if '?' in u:
                query = u.split('?', 1)[1]
                for pair in query.split('&'):
                    name = pair.split('=', 1)[0]
                    if name and name != 'FUZZ':
                        params.add(name)

        result.findings = [{'url': u} for u in urls]
        result.parsed_data = {
            'total_urls': len(urls),
            'unique_params': sorted(params),
            'total_params': len(params),
        }
        return result


# ---------------------------------------------------------------------------
# Dirsearch Adapter — Web Path Scanner
# ---------------------------------------------------------------------------
class DirsearchAdapter:
    """Integration with Dirsearch for web path scanning.

    GitHub: https://github.com/maurosoria/dirsearch
    Web path scanner with smart wordlist, multiple extensions,
    and various output formats.
    """

    TOOL_NAME = 'dirsearch'

    def is_available(self) -> bool:
        return shutil.which('dirsearch') is not None

    def run(self, target: str, extensions: str = 'php,html,js,txt',
            wordlist: str = '', threads: int = 30,
            timeout: int = 300) -> ToolResult:
        """Run Dirsearch path scanner.

        Args:
            target: URL to scan.
            extensions: File extensions (e.g., 'php,html,js').
            wordlist: Custom wordlist path.
            threads: Number of threads.
            timeout: Max seconds.
        """
        if not self.is_available():
            return ToolResult(tool=self.TOOL_NAME, target=target, success=False,
                              error='dirsearch not installed')

        with tempfile.NamedTemporaryFile(suffix='.json', delete=False,
                                         mode='w') as tmp:
            json_path = tmp.name

        cmd = ['dirsearch', '-u', target, '-e', extensions,
               '-t', str(threads), '--format', 'json',
               '-o', json_path, '-q']

        if wordlist and os.path.isfile(wordlist):
            cmd += ['-w', wordlist]

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

        try:
            if os.path.isfile(json_path):
                result.findings = self._parse_json(json_path)
                result.parsed_data = {'total_results': len(result.findings)}
        finally:
            if os.path.isfile(json_path):
                os.unlink(json_path)

        return result

    def _parse_json(self, json_path: str) -> List[dict]:
        """Parse Dirsearch JSON output."""
        findings = []
        try:
            with open(json_path, 'r') as f:
                data = json.load(f)
                if isinstance(data, dict):
                    for _url, entries in data.items():
                        if isinstance(entries, list):
                            for entry in entries:
                                findings.append({
                                    'url': entry.get('url', ''),
                                    'status': entry.get('status', 0),
                                    'content_length': entry.get('content-length', 0),
                                    'content_type': entry.get('content-type', ''),
                                    'redirect': entry.get('redirect', ''),
                                })
                elif isinstance(data, list):
                    for entry in data:
                        findings.append({
                            'url': entry.get('url', ''),
                            'status': entry.get('status', 0),
                            'content_length': entry.get('content-length', 0),
                        })
        except (json.JSONDecodeError, IOError, OSError):
            pass
        return findings


# ===========================================================================
# Recon Arsenal — Central Facade
# ===========================================================================
class ReconArsenal:
    """Central facade for all advanced reconnaissance & discovery tools.

    Manages 15 best-in-class security tools from top GitHub repositories.
    Provides unified interface for tool discovery, execution, and
    orchestrated reconnaissance workflows.
    """

    # Tool categories for organized execution
    CATEGORIES = {
        'subdomain': ['amass', 'dnsx'],
        'http_probe': ['httpx'],
        'crawler': ['katana', 'hakrawler'],
        'url_harvest': ['gau', 'waybackurls', 'paramspider'],
        'param_discovery': ['arjun'],
        'dir_bruteforce': ['ffuf', 'gobuster', 'feroxbuster', 'dirsearch'],
        'port_scan': ['masscan', 'rustscan'],
    }

    def __init__(self):
        self.amass = AmassAdapter()
        self.httpx = HttpxAdapter()
        self.katana = KatanaAdapter()
        self.dnsx = DnsxAdapter()
        self.ffuf = FfufAdapter()
        self.gau = GauAdapter()
        self.waybackurls = WaybackurlsAdapter()
        self.gobuster = GobusterAdapter()
        self.feroxbuster = FeroxbusterAdapter()
        self.masscan = MasscanAdapter()
        self.rustscan = RustscanAdapter()
        self.hakrawler = HakrawlerAdapter()
        self.arjun = ArjunAdapter()
        self.paramspider = ParamSpiderAdapter()
        self.dirsearch = DirsearchAdapter()

        self._adapters: Dict[str, object] = {
            'amass': self.amass,
            'httpx': self.httpx,
            'katana': self.katana,
            'dnsx': self.dnsx,
            'ffuf': self.ffuf,
            'gau': self.gau,
            'waybackurls': self.waybackurls,
            'gobuster': self.gobuster,
            'feroxbuster': self.feroxbuster,
            'masscan': self.masscan,
            'rustscan': self.rustscan,
            'hakrawler': self.hakrawler,
            'arjun': self.arjun,
            'paramspider': self.paramspider,
            'dirsearch': self.dirsearch,
        }

    def get_available_tools(self) -> Dict[str, bool]:
        """Return availability status of all recon arsenal tools."""
        return {name: adapter.is_available()
                for name, adapter in self._adapters.items()}

    def get_tools_by_category(self) -> Dict[str, Dict[str, bool]]:
        """Return tool availability organized by category."""
        result = {}
        avail = self.get_available_tools()
        for category, tools in self.CATEGORIES.items():
            result[category] = {t: avail.get(t, False) for t in tools}
        return result

    def run_tool(self, tool_name: str, target: str, **kwargs) -> ToolResult:
        """Run a specific recon tool by name."""
        adapter = self._adapters.get(tool_name)
        if not adapter:
            return ToolResult(
                tool=tool_name, target=target, success=False,
                error=f'Unknown tool: {tool_name}',
            )
        return adapter.run(target, **kwargs)

    def run_subdomain_enum(self, domain: str) -> Dict[str, ToolResult]:
        """Run all available subdomain enumeration tools."""
        results = {}
        if self.amass.is_available():
            results['amass'] = self.amass.run(domain)
        if self.dnsx.is_available():
            results['dnsx'] = self.dnsx.run(domain)
        return results

    def run_url_harvest(self, domain: str) -> Dict[str, ToolResult]:
        """Run all available URL harvesting tools."""
        results = {}
        if self.gau.is_available():
            results['gau'] = self.gau.run(domain)
        if self.waybackurls.is_available():
            results['waybackurls'] = self.waybackurls.run(domain)
        if self.paramspider.is_available():
            results['paramspider'] = self.paramspider.run(domain)
        return results

    def run_content_discovery(self, target: str, wordlist: str = '') -> Dict[str, ToolResult]:
        """Run all available content/directory discovery tools."""
        results = {}
        kwargs = {}
        if wordlist:
            kwargs['wordlist'] = wordlist
        if self.ffuf.is_available():
            results['ffuf'] = self.ffuf.run(target, **kwargs)
        if self.gobuster.is_available():
            results['gobuster'] = self.gobuster.run(target, **kwargs)
        if self.feroxbuster.is_available():
            results['feroxbuster'] = self.feroxbuster.run(target, **kwargs)
        if self.dirsearch.is_available():
            results['dirsearch'] = self.dirsearch.run(target)
        return results

    def run_http_probe(self, target: str) -> Dict[str, ToolResult]:
        """Run HTTP probing tools."""
        results = {}
        if self.httpx.is_available():
            results['httpx'] = self.httpx.run(target)
        return results

    def run_port_scan(self, target: str, ports: str = '1-65535') -> Dict[str, ToolResult]:
        """Run all available fast port scanners."""
        results = {}
        if self.masscan.is_available():
            results['masscan'] = self.masscan.run(target, ports=ports)
        if self.rustscan.is_available():
            results['rustscan'] = self.rustscan.run(target)
        return results

    def run_full_recon(self, target: str, domain: str = '') -> Dict[str, ToolResult]:
        """Run comprehensive reconnaissance using all available tools.

        This orchestrates tools in logical order:
        1. Subdomain enumeration (if domain provided)
        2. HTTP probing (live host detection)
        3. URL harvesting (historical URLs)
        4. Web crawling (active discovery)
        5. Content discovery (directory brute-force)
        6. Parameter discovery
        7. Port scanning

        Args:
            target: URL to scan.
            domain: Domain for subdomain/URL enumeration.
        """
        results = {}

        # Phase 1: Subdomain enumeration
        if domain:
            results.update(self.run_subdomain_enum(domain))

        # Phase 2: HTTP probing
        results.update(self.run_http_probe(target))

        # Phase 3: URL harvesting
        if domain:
            results.update(self.run_url_harvest(domain))

        # Phase 4: Web crawling
        if self.katana.is_available():
            results['katana'] = self.katana.run(target)
        if self.hakrawler.is_available():
            results['hakrawler'] = self.hakrawler.run(target)

        # Phase 5: Parameter discovery
        if self.arjun.is_available():
            results['arjun'] = self.arjun.run(target)

        # Phase 6: Port scanning
        if domain:
            results.update(self.run_port_scan(domain))

        return results

    def get_all_tool_info(self) -> List[dict]:
        """Return metadata about all arsenal tools."""
        tool_info = [
            {
                'name': 'amass', 'category': 'subdomain',
                'description': 'OWASP advanced subdomain enumeration & network mapping',
                'github': 'https://github.com/owasp-amass/amass',
                'install': 'go install -v github.com/owasp-amass/amass/v4/...@master',
            },
            {
                'name': 'httpx', 'category': 'http_probe',
                'description': 'Fast HTTP probing with tech detection',
                'github': 'https://github.com/projectdiscovery/httpx',
                'install': 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest',
            },
            {
                'name': 'katana', 'category': 'crawler',
                'description': 'Next-gen web crawler with JS rendering',
                'github': 'https://github.com/projectdiscovery/katana',
                'install': 'go install github.com/projectdiscovery/katana/cmd/katana@latest',
            },
            {
                'name': 'dnsx', 'category': 'subdomain',
                'description': 'Fast multi-purpose DNS toolkit',
                'github': 'https://github.com/projectdiscovery/dnsx',
                'install': 'go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest',
            },
            {
                'name': 'ffuf', 'category': 'dir_bruteforce',
                'description': 'Fast web fuzzer for directory/vhost/param discovery',
                'github': 'https://github.com/ffuf/ffuf',
                'install': 'go install github.com/ffuf/ffuf/v2@latest',
            },
            {
                'name': 'gau', 'category': 'url_harvest',
                'description': 'Get All URLs from Wayback, CommonCrawl, OTX, URLScan',
                'github': 'https://github.com/lc/gau',
                'install': 'go install github.com/lc/gau/v2/cmd/gau@latest',
            },
            {
                'name': 'waybackurls', 'category': 'url_harvest',
                'description': 'Fetch known URLs from Wayback Machine',
                'github': 'https://github.com/tomnomnom/waybackurls',
                'install': 'go install github.com/tomnomnom/waybackurls@latest',
            },
            {
                'name': 'gobuster', 'category': 'dir_bruteforce',
                'description': 'Directory/DNS/vhost brute-forcing tool',
                'github': 'https://github.com/OJ/gobuster',
                'install': 'go install github.com/OJ/gobuster/v3@latest',
            },
            {
                'name': 'feroxbuster', 'category': 'dir_bruteforce',
                'description': 'Recursive content discovery written in Rust',
                'github': 'https://github.com/epi052/feroxbuster',
                'install': 'cargo install feroxbuster',
            },
            {
                'name': 'masscan', 'category': 'port_scan',
                'description': 'Fastest Internet port scanner (10M pps)',
                'github': 'https://github.com/robertdavidgraham/masscan',
                'install': 'apt install masscan',
            },
            {
                'name': 'rustscan', 'category': 'port_scan',
                'description': 'Ultra-fast port scanner with Nmap integration',
                'github': 'https://github.com/RustScan/RustScan',
                'install': 'cargo install rustscan',
            },
            {
                'name': 'hakrawler', 'category': 'crawler',
                'description': 'Fast web crawler for URL/JS endpoint discovery',
                'github': 'https://github.com/hakluke/hakrawler',
                'install': 'go install github.com/hakluke/hakrawler@latest',
            },
            {
                'name': 'arjun', 'category': 'param_discovery',
                'description': 'HTTP parameter discovery suite',
                'github': 'https://github.com/s0md3v/Arjun',
                'install': 'pip3 install arjun',
            },
            {
                'name': 'paramspider', 'category': 'url_harvest',
                'description': 'Mining parameters from web archives',
                'github': 'https://github.com/devanshbatham/ParamSpider',
                'install': 'pip3 install paramspider',
            },
            {
                'name': 'dirsearch', 'category': 'dir_bruteforce',
                'description': 'Web path scanner with smart wordlist',
                'github': 'https://github.com/maurosoria/dirsearch',
                'install': 'pip3 install dirsearch',
            },
        ]

        avail = self.get_available_tools()
        for info in tool_info:
            info['available'] = avail.get(info['name'], False)

        return tool_info
