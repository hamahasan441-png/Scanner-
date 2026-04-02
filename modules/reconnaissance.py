#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Reconnaissance Module

DNS enumeration (forward, reverse, MX, NS, TXT), technology
detection, and structured WHOIS lookup.
"""

import re
import socket
import subprocess
from urllib.parse import urlparse
from typing import Dict, List, Optional

from config import Colors


# ── WHOIS fields we care about ───────────────────────────────────────────
_WHOIS_KEYS = {
    'registrar',
    'creation date', 'created',
    'expiration date', 'expiry date', 'registry expiry date',
    'updated date',
    'name server', 'nserver',
    'registrant organization', 'registrant name',
    'registrant country',
    'dnssec',
    'status', 'domain status',
}


class ReconModule:
    """Reconnaissance Module"""

    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.verbose = engine.config.get('verbose', False)

    def run(self, target: str):
        """Run reconnaissance"""
        print(f"\n{Colors.BOLD}{'─' * 60}{Colors.RESET}")
        print(f"{Colors.CYAN}  Reconnaissance{Colors.RESET}")
        print(f"{Colors.BOLD}{'─' * 60}{Colors.RESET}\n")

        domain = urlparse(target).hostname or urlparse(target).netloc

        self._dns_lookup(domain)
        self._detect_tech(target)
        self._whois_lookup(domain)
        self._analyze_ssl_tls(domain)
        self._audit_security_headers(target)
        self._detect_subdomain_takeover(domain)
        self._detect_cloud_assets(target)
        self._enumerate_api_endpoints(target)

    # ─── DNS ─────────────────────────────────────────────────────────

    def _dns_lookup(self, domain: str):
        """DNS enumeration — A, reverse, MX, NS, TXT records."""
        try:
            ip = socket.gethostbyname(domain)
            print(f"{Colors.info(f'DNS A: {domain} → {ip}')}")

            # Reverse DNS
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                print(f"{Colors.info(f'Reverse DNS: {ip} → {hostname}')}")
            except (socket.herror, OSError):
                if self.verbose:
                    print(f"{Colors.info('Reverse DNS: no PTR record')}")

            # Additional records via dnspython (optional dependency)
            self._dns_extra_records(domain)

        except socket.gaierror as e:
            print(f"{Colors.warning(f'DNS lookup failed: {e}')}")
        except Exception as e:
            if self.verbose:
                print(f"{Colors.error(f'DNS lookup error: {e}')}")

    def _dns_extra_records(self, domain: str):
        """Query MX, NS, and TXT records (requires dnspython)."""
        try:
            import dns.resolver
        except ImportError:
            if self.verbose:
                print(f"{Colors.info('dnspython not installed — skipping MX/NS/TXT')}")
            return

        for rtype in ('MX', 'NS', 'TXT'):
            try:
                answers = dns.resolver.resolve(domain, rtype)
                for rdata in answers:
                    text = str(rdata).strip('"')
                    print(f"{Colors.info(f'DNS {rtype}: {text}')}")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            except Exception as e:
                if self.verbose:
                    print(f"{Colors.warning(f'DNS {rtype} error: {e}')}")

    # ─── Technology detection ────────────────────────────────────────

    def _detect_tech(self, url: str):
        """Detect technologies from HTTP headers and body."""
        try:
            response = self.requester.request(url, 'GET')
            if not response:
                return

            tech: List[str] = []
            headers = response.headers

            # Server header
            if 'Server' in headers:
                tech.append(f"Server: {headers['Server']}")

            # X-Powered-By
            if 'X-Powered-By' in headers:
                tech.append(f"Powered by: {headers['X-Powered-By']}")

            # Security headers (note presence / absence)
            for hdr in ('X-Frame-Options', 'Content-Security-Policy',
                        'Strict-Transport-Security', 'X-Content-Type-Options'):
                if hdr in headers:
                    tech.append(f"{hdr}: {headers[hdr][:80]}")

            # Cookies → language hints
            if 'Set-Cookie' in headers:
                cookies = headers['Set-Cookie']
                if 'PHPSESSID' in cookies:
                    tech.append('PHP')
                if 'ASP.NET_SessionId' in cookies:
                    tech.append('ASP.NET')
                if 'JSESSIONID' in cookies:
                    tech.append('Java')
                if 'connect.sid' in cookies:
                    tech.append('Node.js / Express')

            # Body analysis
            body = response.text[:5000]

            frameworks = {
                'WordPress': r'/wp-content|wp-includes',
                'Drupal': r'Drupal|drupal',
                'Joomla': r'Joomla|joomla',
                'React': r'react|reactjs',
                'Angular': r'angular|ng-',
                'Vue.js': r'vue\.js|vuejs',
                'jQuery': r'jquery',
                'Bootstrap': r'bootstrap',
                'Laravel': r'laravel',
                'Django': r'django|csrfmiddlewaretoken',
                'Flask': r'flask',
                'Express.js': r'express',
                'Ruby on Rails': r'rails',
                'Spring': r'spring',
                'Next.js': r'_next/static|__NEXT_DATA__',
            }

            for fw, pattern in frameworks.items():
                if re.search(pattern, body, re.IGNORECASE):
                    tech.append(fw)

            if tech:
                print(f"{Colors.info('Technologies detected:')}")
                for t in tech:
                    print(f"  - {t}")
            else:
                print(f"{Colors.info('No technologies positively identified')}")

        except Exception as e:
            if self.verbose:
                print(f"{Colors.error(f'Tech detection error: {e}')}")

    # ─── WHOIS ───────────────────────────────────────────────────────

    def _whois_lookup(self, domain: str):
        """Structured WHOIS lookup via system ``whois`` command."""
        try:
            result = subprocess.run(
                ['whois', domain],
                capture_output=True,
                text=True,
                timeout=15,
            )

            if result.returncode != 0:
                if self.verbose:
                    print(f"{Colors.warning('WHOIS command returned non-zero')}")
                return

            parsed = self._parse_whois(result.stdout)
            if parsed:
                print(f"\n{Colors.info('WHOIS Information:')}")
                for key, value in parsed.items():
                    print(f"  {key:30s}: {value}")
            else:
                print(f"{Colors.info('WHOIS: no structured data extracted')}")

        except FileNotFoundError:
            if self.verbose:
                print(f"{Colors.info('whois command not found — skipping WHOIS lookup')}")
        except subprocess.TimeoutExpired:
            if self.verbose:
                print(f"{Colors.warning('WHOIS lookup timed out')}")
        except Exception as e:
            if self.verbose:
                print(f"{Colors.error(f'WHOIS error: {e}')}")

    # ─── SSL/TLS ──────────────────────────────────────────────────────

    def _analyze_ssl_tls(self, domain):
        """SSL/TLS certificate analysis"""
        import ssl
        import socket as _socket
        try:
            context = ssl.create_default_context()
            with _socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Extract SAN
                    san = cert.get('subjectAltName', ())
                    san_names = [name for typ, name in san if typ == 'DNS']
                    
                    # Check expiry
                    import datetime
                    not_after = cert.get('notAfter', '')
                    
                    # Certificate info
                    issuer = dict(x[0] for x in cert.get('issuer', ()))
                    subject = dict(x[0] for x in cert.get('subject', ()))
                    
                    issuer_name = issuer.get("organizationName", "Unknown")
                    subject_cn = subject.get("commonName", "Unknown")
                    san_str = ", ".join(san_names[:10])
                    
                    print(f"{Colors.info(f'SSL Issuer: {issuer_name}')}")
                    print(f"{Colors.info(f'SSL Subject: {subject_cn}')}")
                    print(f"{Colors.info(f'SSL Expires: {not_after}')}")
                    if san_names:
                        print(f"{Colors.info(f'SSL SANs: {san_str}')}")
                    
                    # Check for weaknesses
                    if len(san_names) > 20:
                        from core.engine import Finding
                        finding = Finding(
                            technique="Recon (Wildcard/Many SANs)",
                            url=f"https://{domain}", severity='INFO', confidence=0.8,
                            param='SSL', payload=f'{len(san_names)} SANs',
                            evidence=f"Certificate has {len(san_names)} SANs — potential shared hosting",
                        )
                        self.engine.add_finding(finding)
        except Exception as e:
            if self.verbose:
                print(f"{Colors.warning(f'SSL/TLS analysis error: {e}')}")

    # ─── Security Headers ───────────────────────────────────────────

    def _audit_security_headers(self, url):
        """Audit HTTP security headers"""
        try:
            response = self.requester.request(url, 'GET')
            if not response:
                return
            
            headers = response.headers
            missing_headers = []
            
            security_headers = {
                'Strict-Transport-Security': 'HSTS',
                'X-Frame-Options': 'Clickjacking Protection',
                'Content-Security-Policy': 'CSP',
                'X-Content-Type-Options': 'MIME Sniffing Protection',
                'Permissions-Policy': 'Permissions Policy',
                'Referrer-Policy': 'Referrer Policy',
                'X-XSS-Protection': 'XSS Protection',
            }
            
            for header, description in security_headers.items():
                if header not in headers:
                    missing_headers.append(f"{header} ({description})")
                else:
                    print(f"{Colors.info(f'Security Header: {header}: {headers[header][:80]}')}")
            
            if missing_headers:
                from core.engine import Finding
                severity = 'HIGH' if len(missing_headers) >= 4 else 'MEDIUM' if len(missing_headers) >= 2 else 'LOW'
                finding = Finding(
                    technique="Recon (Missing Security Headers)",
                    url=url, severity=severity, confidence=0.95,
                    param='Headers', payload=f'{len(missing_headers)} missing',
                    evidence=f"Missing: {'; '.join(missing_headers[:5])}",
                )
                self.engine.add_finding(finding)
        except Exception as e:
            if self.verbose:
                print(f"{Colors.warning(f'Header audit error: {e}')}")

    # ─── Subdomain Takeover ─────────────────────────────────────────

    def _detect_subdomain_takeover(self, domain):
        """Check for subdomain takeover via dangling CNAMEs"""
        takeover_signatures = {
            'github.io': "There isn't a GitHub Pages site here",
            'herokuapp.com': 'No such app',
            'amazonaws.com': 'NoSuchBucket',
            'azure-api.net': 'not found',
            'cloudfront.net': 'Bad request',
            'ghost.io': 'Domain is not configured',
            'shopify.com': 'Sorry, this shop is currently unavailable',
            'tumblr.com': "There's nothing here",
            'wordpress.com': 'Do you want to register',
            'zendesk.com': 'Help Center Closed',
        }
        
        try:
            import dns.resolver
        except ImportError:
            return
        
        subdomains = ['www', 'mail', 'blog', 'dev', 'staging', 'api', 'cdn', 'admin']
        
        for sub in subdomains:
            fqdn = f"{sub}.{domain}"
            try:
                answers = dns.resolver.resolve(fqdn, 'CNAME')
                for rdata in answers:
                    cname = str(rdata.target).rstrip('.')
                    for service, signature in takeover_signatures.items():
                        if service in cname:
                            try:
                                resp = self.requester.request(f"http://{fqdn}", 'GET')
                                if resp and signature.lower() in resp.text.lower():
                                    from core.engine import Finding
                                    finding = Finding(
                                        technique="Recon (Subdomain Takeover)",
                                        url=f"http://{fqdn}", severity='HIGH', confidence=0.85,
                                        param='CNAME', payload=cname,
                                        evidence=f"CNAME points to {service} which shows: {signature}",
                                    )
                                    self.engine.add_finding(finding)
                            except Exception:
                                pass
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, Exception):
                continue

    # ─── Cloud Assets ───────────────────────────────────────────────

    def _detect_cloud_assets(self, url):
        """Detect cloud storage assets (S3, Azure Blobs, GCP)"""
        try:
            response = self.requester.request(url, 'GET')
            if not response:
                return
            
            text = response.text
            cloud_patterns = {
                'AWS S3': [
                    r'https?://[\w.-]+\.s3[\w.-]*\.amazonaws\.com',
                    r'https?://s3[\w.-]*\.amazonaws\.com/[\w.-]+',
                    r's3://[\w.-]+',
                ],
                'Azure Blob': [
                    r'https?://[\w.-]+\.blob\.core\.windows\.net',
                ],
                'GCP Storage': [
                    r'https?://storage\.googleapis\.com/[\w.-]+',
                    r'https?://[\w.-]+\.storage\.googleapis\.com',
                    r'gs://[\w.-]+',
                ],
            }
            
            found = {}
            for provider, patterns in cloud_patterns.items():
                for pattern in patterns:
                    matches = re.findall(pattern, text)
                    if matches:
                        found.setdefault(provider, []).extend(matches[:3])
            
            if found:
                all_assets = []
                for provider, assets in found.items():
                    all_assets.extend([f"{provider}: {a}" for a in assets])
                from core.engine import Finding
                finding = Finding(
                    technique="Recon (Cloud Asset Detection)",
                    url=url, severity='INFO', confidence=0.9,
                    param='N/A', payload=f'{len(all_assets)} assets',
                    evidence="; ".join(all_assets[:5]),
                )
                self.engine.add_finding(finding)
        except Exception:
            pass

    # ─── API Endpoints ──────────────────────────────────────────────

    def _enumerate_api_endpoints(self, url):
        """Detect API versioning and enumerate endpoints"""
        base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        api_paths = [
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/api/docs', '/api/swagger', '/api/openapi',
            '/swagger.json', '/openapi.json',
            '/graphql', '/graphiql',
            '/api/health', '/api/status', '/api/version',
            '/.well-known/openid-configuration',
        ]
        
        found_endpoints = []
        for path in api_paths:
            try:
                test_url = f"{base_url}{path}"
                response = self.requester.request(test_url, 'GET')
                if response and response.status_code in (200, 301, 302):
                    found_endpoints.append(f"{path} ({response.status_code})")
            except Exception:
                continue
        
        if found_endpoints:
            print(f"{Colors.info(f'API Endpoints: {len(found_endpoints)} found')}")
            for ep in found_endpoints:
                print(f"  {Colors.info(ep)}")
            from core.engine import Finding
            finding = Finding(
                technique="Recon (API Endpoint Enumeration)",
                url=base_url, severity='INFO', confidence=0.85,
                param='N/A', payload=f'{len(found_endpoints)} endpoints',
                evidence="; ".join(found_endpoints[:5]),
            )
            self.engine.add_finding(finding)

    # ─── WHOIS parsing ──────────────────────────────────────────────

    @staticmethod
    def _parse_whois(raw: str) -> Dict[str, str]:
        """Extract key fields from raw WHOIS output."""
        parsed: Dict[str, str] = {}
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith('%') or line.startswith('#'):
                continue
            if ':' not in line:
                continue
            key, _, value = line.partition(':')
            key_lower = key.strip().lower()
            value = value.strip()
            if not value:
                continue
            if key_lower in _WHOIS_KEYS or any(k in key_lower for k in _WHOIS_KEYS):
                display_key = key.strip()
                # Keep first occurrence for most fields
                if display_key not in parsed:
                    parsed[display_key] = value
        return parsed
