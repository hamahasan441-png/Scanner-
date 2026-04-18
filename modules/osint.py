#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - OSINT Reconnaissance Module
Google dorking, GitHub secret leak detection, Wayback Machine harvesting,
GitHub Code Search API integration, secret pattern scanning
"""

import re
from urllib.parse import urlparse, quote_plus

from config import Config, Payloads


class OSINTModule:
    """OSINT Reconnaissance Module"""

    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.name = "OSINT Recon"
        # Compile secret patterns once for reuse
        self._secret_regexes = []
        for name, pattern in Payloads.SECRET_PATTERNS:
            try:
                self._secret_regexes.append((name, re.compile(pattern)))
            except re.error:
                pass

    def test(self, url, method, param, value):
        """Not used for OSINT — recon is URL-based"""

    def test_url(self, url):
        """Run OSINT reconnaissance on target URL"""
        domain = urlparse(url).hostname or urlparse(url).netloc
        self._generate_google_dorks(domain)
        self._check_github_leaks(domain)
        self._scan_github_code_search(domain)
        self._wayback_harvest(url)
        self._check_robots_sitemap(url)
        self._scan_response_secrets(url)
        self._query_securitytrails(domain)
        self._query_alienvault_otx(domain)

    def _generate_google_dorks(self, domain):
        """Generate Google dorking payloads"""
        dorks = [
            # ── File exposure dorks ──
            f"site:{domain} filetype:sql",
            f"site:{domain} filetype:env",
            f"site:{domain} filetype:log",
            f"site:{domain} filetype:conf",
            f"site:{domain} filetype:bak",
            f"site:{domain} filetype:xml sitemap",
            # ── Extended sensitive file types ──
            f"site:{domain} ext:log | ext:sql | ext:env | ext:json | ext:yaml | ext:conf | ext:cfg",
            # ── Directory listing dorks ──
            f'site:{domain} intitle:"index of" "parent directory"',
            f'site:{domain} intitle:"index of"',
            # ── Admin/API/config paths ──
            f"site:{domain} inurl:admin",
            f"site:{domain} inurl:login",
            f"site:{domain} inurl:api",
            f"site:{domain} inurl:admin | inurl:api | inurl:config | inurl:backup | inurl:upload",
            f"site:{domain} inurl:wp-config",
            f'site:{domain} inurl:".git"',
            f"site:{domain} inurl:swagger",
            # ── Credential / secret dorks ──
            f'site:{domain} "access_key" | "secret_key" | "api_key" | "password" | "token"',
            f'site:{domain} "BEGIN RSA PRIVATE KEY"',
            # ── Technology-specific dorks ──
            f"site:{domain} ext:php intitle:phpinfo",
            f"site:{domain} ext:asp | ext:aspx | ext:jsp",
            f"site:{domain} inurl:wp-content | inurl:wp-includes",
            # ── Backup / old files ──
            f"site:{domain} ext:bak | ext:old | ext:backup | ext:zip | ext:tar | ext:gz",
            f"site:{domain} ext:swp | ext:save | ext:orig",
            # ── Version control exposure ──
            f'site:{domain} inurl:".svn"',
            f"site:{domain} inurl:.DS_Store",
        ]
        from core.engine import Finding

        finding = Finding(
            technique="OSINT (Google Dorks Generated)",
            url=f"https://www.google.com/search?q=site:{domain}",
            severity="INFO",
            confidence=1.0,
            param="N/A",
            payload=f"{len(dorks)} dorks generated",
            evidence="; ".join(dorks[:5]) + f"... ({len(dorks)} total)",
        )
        self.engine.add_finding(finding)

    def _check_github_leaks(self, domain):
        """Check for potential GitHub/GitLab secret leaks"""
        search_queries = [
            f'"{domain}" password',
            f'"{domain}" api_key',
            f'"{domain}" secret',
            f'"{domain}" token',
            f'"{domain}" AWS_ACCESS_KEY',
            f'"{domain}" .env',
            f'"{domain}" wp-config',
            f'"{domain}" id_rsa',
            f'"{domain}" private_key',
        ]
        from core.engine import Finding

        finding = Finding(
            technique="OSINT (GitHub Leak Queries Generated)",
            url=f"https://github.com/search?q={domain}&type=code",
            severity="INFO",
            confidence=1.0,
            param="N/A",
            payload=f"{len(search_queries)} queries generated",
            evidence="; ".join(search_queries[:3]) + f"... ({len(search_queries)} total)",
        )
        self.engine.add_finding(finding)

    def _scan_github_code_search(self, domain):
        """Query GitHub Code Search API for exposed secrets referencing the target domain.

        Uses the GitHub REST API ``/search/code`` endpoint to find
        code snippets on public repositories that mention the target
        domain alongside sensitive keywords (passwords, tokens, keys).
        Requires a GITHUB_TOKEN for higher rate limits.
        """
        if not Config.GITHUB_TOKEN:
            return  # Code search API requires authentication

        from core.engine import Finding

        keywords = ["password", "secret", "api_key", "token", "private_key"]
        total_hits = 0
        leak_evidence = []

        headers = {
            "Accept": "application/vnd.github.v3+json",
            "Authorization": f"Bearer {Config.GITHUB_TOKEN}",
        }

        for keyword in keywords:
            try:
                query = f'"{domain}" {keyword}'
                api_url = f"https://api.github.com/search/code?" f"q={quote_plus(query)}&per_page=3"
                resp = self._github_request(api_url, headers)
                if not resp:
                    continue

                data = resp.json() if hasattr(resp, "json") and callable(resp.json) else {}
                count = data.get("total_count", 0)
                if count > 0:
                    total_hits += count
                    for item in data.get("items", [])[:2]:
                        repo = item.get("repository", {}).get("full_name", "")
                        path = item.get("path", "")
                        if repo and path:
                            leak_evidence.append(f"{repo}/{path}")
            except Exception:
                continue

        if total_hits > 0:
            severity = "HIGH" if total_hits > 10 else "MEDIUM" if total_hits > 3 else "LOW"
            evidence_str = f"Found {total_hits} code matches on GitHub"
            if leak_evidence:
                evidence_str += ": " + "; ".join(leak_evidence[:5])
            finding = Finding(
                technique="OSINT (GitHub Code Search — Leak Detection)",
                url=f"https://github.com/search?q={quote_plus(domain)}&type=code",
                severity=severity,
                confidence=0.7,
                param="N/A",
                payload=f"{total_hits} potential leaks across {len(keywords)} keywords",
                evidence=evidence_str,
            )
            self.engine.add_finding(finding)

    def _scan_response_secrets(self, url):
        """Scan target HTTP responses for leaked secrets using GitHub-style patterns.

        Fetches the target URL (and common sensitive paths) and scans
        the response body against compiled secret-detection regexes
        from ``Payloads.SECRET_PATTERNS``.
        """
        if not self._secret_regexes:
            return

        from core.engine import Finding

        # Paths that commonly expose secrets
        base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        paths_to_check = [
            url,
            f"{base_url}/.env",
            f"{base_url}/config.js",
            f"{base_url}/wp-config.php.bak",
            f"{base_url}/api/config",
            f"{base_url}/.git/config",
        ]

        _MAX_MATCHES_PER_PATTERN = 2  # Cap per-pattern matches to reduce noise
        found_secrets = []
        for check_url in paths_to_check:
            try:
                resp = self.requester.request(check_url, "GET")
                if not resp or not hasattr(resp, "text") or resp.status_code != 200:
                    continue
                body = resp.text or ""
                if len(body) < 10:
                    continue
                for secret_name, regex in self._secret_regexes:
                    matches = regex.findall(body)
                    if matches:
                        # Redact matched values for safe reporting
                        for m in matches[:_MAX_MATCHES_PER_PATTERN]:
                            redacted = m[:8] + "..." + m[-4:] if len(m) > 16 else m[:4] + "****"
                            found_secrets.append(
                                {
                                    "type": secret_name,
                                    "url": check_url,
                                    "sample": redacted,
                                }
                            )
            except Exception:
                continue

        if found_secrets:
            severity = "CRITICAL" if len(found_secrets) > 3 else "HIGH"
            evidence_parts = []
            for s in found_secrets[:10]:
                evidence_parts.append(f"{s['type']} at {s['url']} ({s['sample']})")
            finding = Finding(
                technique="OSINT (Secret Pattern Scan)",
                url=url,
                severity=severity,
                confidence=0.85,
                param="N/A",
                payload=f"{len(found_secrets)} secrets detected via GitHub-style pattern scanning",
                evidence="; ".join(evidence_parts),
            )
            self.engine.add_finding(finding)

    def _github_request(self, url, headers):
        """Make a GitHub API request using the engine requester or requests lib."""
        try:
            if self.requester and hasattr(self.requester, "session"):
                return self.requester.session.get(url, headers=headers, timeout=10)
            else:
                import requests as _requests

                return _requests.get(url, headers=headers, timeout=10)
        except Exception:
            return None

    def _wayback_harvest(self, url):
        """Harvest URLs from Wayback Machine"""
        domain = urlparse(url).hostname
        wayback_url = (
            f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=text&fl=original&collapse=urlkey&limit=100"
        )
        try:
            response = self.requester.request(wayback_url, "GET")
            if response and response.status_code == 200:
                urls = [line.strip() for line in response.text.strip().split("\n") if line.strip()]
                if urls:
                    interesting = [
                        u
                        for u in urls
                        if any(
                            ext in u.lower()
                            for ext in [".php", ".asp", ".jsp", ".env", ".bak", ".sql", ".conf", "api/", "admin/"]
                        )
                    ]
                    from core.engine import Finding

                    finding = Finding(
                        technique="OSINT (Wayback Machine)",
                        url=wayback_url,
                        severity="INFO",
                        confidence=0.9,
                        param="N/A",
                        payload=f"{len(urls)} URLs found",
                        evidence=f"Found {len(urls)} historical URLs, {len(interesting)} potentially interesting",
                    )
                    self.engine.add_finding(finding)
        except Exception:
            pass

    def _check_robots_sitemap(self, url):
        """Check robots.txt and sitemap for hidden endpoints"""
        base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        findings_data = []

        # Check robots.txt
        try:
            robots_url = f"{base_url}/robots.txt"
            response = self.requester.request(robots_url, "GET")
            if response and response.status_code == 200 and "disallow" in response.text.lower():
                disallowed = re.findall(r"Disallow:\s*(.+)", response.text, re.IGNORECASE)
                if disallowed:
                    findings_data.append(f"robots.txt: {len(disallowed)} disallowed paths")
        except Exception:
            pass

        # Check sitemap
        try:
            sitemap_url = f"{base_url}/sitemap.xml"
            response = self.requester.request(sitemap_url, "GET")
            if response and response.status_code == 200 and "<loc>" in response.text.lower():
                locs = re.findall(r"<loc>(.*?)</loc>", response.text, re.IGNORECASE)
                if locs:
                    findings_data.append(f"sitemap.xml: {len(locs)} URLs")
        except Exception:
            pass

        if findings_data:
            from core.engine import Finding

            finding = Finding(
                technique="OSINT (Robots/Sitemap Analysis)",
                url=base_url,
                severity="INFO",
                confidence=0.9,
                param="N/A",
                payload="robots.txt + sitemap.xml",
                evidence="; ".join(findings_data),
            )
            self.engine.add_finding(finding)

    # ─── SecurityTrails API ─────────────────────────────────────────

    def _query_securitytrails(self, domain):
        """Query SecurityTrails API for passive subdomain enumeration.

        Uses the SecurityTrails REST API to discover subdomains without
        sending any requests directly to the target. Requires a
        SECURITYTRAILS_API_KEY environment variable.
        """
        if not Config.SECURITYTRAILS_API_KEY:
            return

        from core.engine import Finding

        api_url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {
            "Accept": "application/json",
            "APIKEY": Config.SECURITYTRAILS_API_KEY,
        }

        try:
            resp = self._api_request(api_url, headers)
            if not resp:
                return

            data = resp.json() if hasattr(resp, "json") and callable(resp.json) else {}
            subdomains_list = data.get("subdomains", [])
            if subdomains_list:
                full_subs = [f"{s}.{domain}" for s in subdomains_list]
                finding = Finding(
                    technique="OSINT (SecurityTrails Subdomain Enumeration)",
                    url=f"https://securitytrails.com/domain/{domain}",
                    severity="INFO",
                    confidence=0.95,
                    param="N/A",
                    payload=f"{len(full_subs)} subdomains discovered",
                    evidence=f"Subdomains: {', '.join(sorted(full_subs)[:15])}",
                )
                self.engine.add_finding(finding)
        except Exception:
            pass

    # ─── AlienVault OTX API ─────────────────────────────────────────

    def _query_alienvault_otx(self, domain):
        """Query AlienVault OTX for passive DNS and subdomain data.

        Uses the OTX DirectConnect API to gather passive DNS records
        and associated hostnames for the target domain. Optionally
        uses an OTX_API_KEY for authenticated requests.
        """
        from core.engine import Finding

        api_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        headers = {"Accept": "application/json"}
        if Config.OTX_API_KEY:
            headers["X-OTX-API-KEY"] = Config.OTX_API_KEY

        try:
            resp = self._api_request(api_url, headers)
            if not resp:
                return

            data = resp.json() if hasattr(resp, "json") and callable(resp.json) else {}
            passive_dns = data.get("passive_dns", [])
            if not passive_dns:
                return

            hostnames = set()
            ip_addresses = set()
            for record in passive_dns:
                hostname = record.get("hostname", "")
                address = record.get("address", "")
                if hostname and domain in hostname:
                    hostnames.add(hostname)
                if address:
                    ip_addresses.add(address)

            if hostnames or ip_addresses:
                evidence_parts = []
                if hostnames:
                    evidence_parts.append(
                        f"Hostnames: {', '.join(sorted(hostnames)[:10])}"
                    )
                if ip_addresses:
                    evidence_parts.append(
                        f"IPs: {', '.join(sorted(ip_addresses)[:10])}"
                    )
                finding = Finding(
                    technique="OSINT (AlienVault OTX Passive DNS)",
                    url=f"https://otx.alienvault.com/indicator/domain/{domain}",
                    severity="INFO",
                    confidence=0.9,
                    param="N/A",
                    payload=f"{len(hostnames)} hostnames, {len(ip_addresses)} IPs",
                    evidence="; ".join(evidence_parts),
                )
                self.engine.add_finding(finding)
        except Exception:
            pass

    def _api_request(self, url, headers):
        """Make an API request using the engine requester or requests lib."""
        try:
            if self.requester and hasattr(self.requester, "session"):
                return self.requester.session.get(url, headers=headers, timeout=10)
            else:
                import requests as _requests

                return _requests.get(url, headers=headers, timeout=10)
        except Exception:
            return None
