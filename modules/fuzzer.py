#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Fuzzer Module
Parameter, header, HTTP method, and virtual host fuzzing
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
from urllib.parse import urlparse, urljoin, urlencode, parse_qs

from config import Colors


class FuzzerModule:
    """Fuzzer Module for parameter, header, method, and vhost enumeration"""
    
    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.name = "Fuzzer"
        
        self.common_params = [
            'id', 'user', 'username', 'email', 'token', 'page', 'search',
            'query', 'q', 'file', 'path', 'url', 'redirect', 'next',
            'callback', 'cmd', 'exec', 'action', 'type', 'sort', 'order',
            'limit', 'offset', 'format', 'lang', 'debug', 'test', 'admin',
            'key', 'api_key', 'secret', 'password', 'pass', 'auth',
        ]
        
        self.fuzz_headers = [
            'X-Forwarded-For', 'X-Real-IP', 'X-Originating-IP',
            'X-Remote-IP', 'X-Remote-Addr', 'X-Custom-IP-Authorization',
            'X-Original-URL', 'X-Rewrite-URL', 'X-Host',
            'X-Forwarded-Host', 'X-Debug', 'X-Debug-Mode',
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
        
        # External tool integrations
        self._paramspider_discover(url)
        self._ffufai_fuzz(url)

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
                test_values = ['127.0.0.1', 'localhost', 'admin', 'true', '1']
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
