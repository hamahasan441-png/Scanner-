#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Reconnaissance Module

DNS enumeration (forward, reverse, MX, NS, TXT), technology
detection, structured WHOIS lookup, VHost discovery,
and wildcard DNS detection.
"""

import re
import socket
import string
import subprocess
import random
from urllib.parse import urlparse
from typing import Dict, List

from config import Colors

# ── WHOIS fields we care about ───────────────────────────────────────────
_WHOIS_KEYS = {
    "registrar",
    "creation date",
    "created",
    "expiration date",
    "expiry date",
    "registry expiry date",
    "updated date",
    "name server",
    "nserver",
    "registrant organization",
    "registrant name",
    "registrant country",
    "dnssec",
    "status",
    "domain status",
}


class ReconModule:
    """Reconnaissance Module"""

    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.verbose = engine.config.get("verbose", False)

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
        self._detect_wildcard_dns(domain)
        self._detect_subdomain_takeover(domain)
        self._detect_cloud_assets(target)
        self._enumerate_api_endpoints(target)
        self._certificate_transparency(domain)
        self._dns_zone_transfer(domain)
        self._check_email_security(domain)
        self._detect_http2_alpn(domain)
        self._detect_cms_version(target)
        self._cors_preflight_check(target)
        self._discover_vhosts(target, domain)

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

        for rtype in ("MX", "NS", "TXT"):
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
            response = self.requester.request(url, "GET")
            if not response:
                return

            tech: List[str] = []
            headers = response.headers

            # Server header
            if "Server" in headers:
                tech.append(f"Server: {headers['Server']}")

            # X-Powered-By
            if "X-Powered-By" in headers:
                tech.append(f"Powered by: {headers['X-Powered-By']}")

            # Security headers (note presence / absence)
            for hdr in (
                "X-Frame-Options",
                "Content-Security-Policy",
                "Strict-Transport-Security",
                "X-Content-Type-Options",
            ):
                if hdr in headers:
                    tech.append(f"{hdr}: {headers[hdr][:80]}")

            # Cookies → language hints
            if "Set-Cookie" in headers:
                cookies = headers["Set-Cookie"]
                if "PHPSESSID" in cookies:
                    tech.append("PHP")
                if "ASP.NET_SessionId" in cookies:
                    tech.append("ASP.NET")
                if "JSESSIONID" in cookies:
                    tech.append("Java")
                if "connect.sid" in cookies:
                    tech.append("Node.js / Express")

            # Body analysis
            body = response.text[:5000]

            frameworks = {
                "WordPress": r"/wp-content|wp-includes",
                "Drupal": r"Drupal|drupal",
                "Joomla": r"Joomla|joomla",
                "React": r"react|reactjs",
                "Angular": r"angular|ng-",
                "Vue.js": r"vue\.js|vuejs",
                "jQuery": r"jquery",
                "Bootstrap": r"bootstrap",
                "Laravel": r"laravel",
                "Django": r"django|csrfmiddlewaretoken",
                "Flask": r"flask",
                "Express.js": r"express",
                "Ruby on Rails": r"rails",
                "Spring": r"spring",
                "Next.js": r"_next/static|__NEXT_DATA__",
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
                ["whois", domain],
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
                    san = cert.get("subjectAltName", ())
                    san_names = [name for typ, name in san if typ == "DNS"]

                    # Check expiry
                    not_after = cert.get("notAfter", "")

                    # Certificate info
                    issuer = dict(x[0] for x in cert.get("issuer", ()))
                    subject = dict(x[0] for x in cert.get("subject", ()))

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
                            url=f"https://{domain}",
                            severity="INFO",
                            confidence=0.8,
                            param="SSL",
                            payload=f"{len(san_names)} SANs",
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
            response = self.requester.request(url, "GET")
            if not response:
                return

            headers = response.headers
            missing_headers = []

            security_headers = {
                "Strict-Transport-Security": "HSTS",
                "X-Frame-Options": "Clickjacking Protection",
                "Content-Security-Policy": "CSP",
                "X-Content-Type-Options": "MIME Sniffing Protection",
                "Permissions-Policy": "Permissions Policy",
                "Referrer-Policy": "Referrer Policy",
                "X-XSS-Protection": "XSS Protection",
            }

            for header, description in security_headers.items():
                if header not in headers:
                    missing_headers.append(f"{header} ({description})")
                else:
                    print(f"{Colors.info(f'Security Header: {header}: {headers[header][:80]}')}")

            if missing_headers:
                from core.engine import Finding

                severity = "HIGH" if len(missing_headers) >= 4 else "MEDIUM" if len(missing_headers) >= 2 else "LOW"
                finding = Finding(
                    technique="Recon (Missing Security Headers)",
                    url=url,
                    severity=severity,
                    confidence=0.95,
                    param="Headers",
                    payload=f"{len(missing_headers)} missing",
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
            "github.io": "There isn't a GitHub Pages site here",
            "herokuapp.com": "No such app",
            "amazonaws.com": "NoSuchBucket",
            "azure-api.net": "not found",
            "cloudfront.net": "Bad request",
            "ghost.io": "Domain is not configured",
            "shopify.com": "Sorry, this shop is currently unavailable",
            "tumblr.com": "There's nothing here",
            "wordpress.com": "Do you want to register",
            "zendesk.com": "Help Center Closed",
        }

        try:
            import dns.resolver
        except ImportError:
            return

        subdomains = ["www", "mail", "blog", "dev", "staging", "api", "cdn", "admin"]

        for sub in subdomains:
            fqdn = f"{sub}.{domain}"
            try:
                answers = dns.resolver.resolve(fqdn, "CNAME")
                for rdata in answers:
                    cname = str(rdata.target).rstrip(".")
                    for service, signature in takeover_signatures.items():
                        if service in cname:
                            try:
                                resp = self.requester.request(f"http://{fqdn}", "GET")
                                if resp and signature.lower() in resp.text.lower():
                                    from core.engine import Finding

                                    finding = Finding(
                                        technique="Recon (Subdomain Takeover)",
                                        url=f"http://{fqdn}",
                                        severity="HIGH",
                                        confidence=0.85,
                                        param="CNAME",
                                        payload=cname,
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
            response = self.requester.request(url, "GET")
            if not response:
                return

            text = response.text
            cloud_patterns = {
                "AWS S3": [
                    r"https?://[\w.-]+\.s3[\w.-]*\.amazonaws\.com",
                    r"https?://s3[\w.-]*\.amazonaws\.com/[\w.-]+",
                    r"s3://[\w.-]+",
                ],
                "Azure Blob": [
                    r"https?://[\w.-]+\.blob\.core\.windows\.net",
                ],
                "GCP Storage": [
                    r"https?://storage\.googleapis\.com/[\w.-]+",
                    r"https?://[\w.-]+\.storage\.googleapis\.com",
                    r"gs://[\w.-]+",
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
                    url=url,
                    severity="INFO",
                    confidence=0.9,
                    param="N/A",
                    payload=f"{len(all_assets)} assets",
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
            "/api",
            "/api/v1",
            "/api/v2",
            "/api/v3",
            "/api/docs",
            "/api/swagger",
            "/api/openapi",
            "/swagger.json",
            "/openapi.json",
            "/graphql",
            "/graphiql",
            "/api/health",
            "/api/status",
            "/api/version",
            "/.well-known/openid-configuration",
        ]

        found_endpoints = []
        for path in api_paths:
            try:
                test_url = f"{base_url}{path}"
                response = self.requester.request(test_url, "GET")
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
                url=base_url,
                severity="INFO",
                confidence=0.85,
                param="N/A",
                payload=f"{len(found_endpoints)} endpoints",
                evidence="; ".join(found_endpoints[:5]),
            )
            self.engine.add_finding(finding)

    # ─── Certificate Transparency ──────────────────────────────────

    def _certificate_transparency(self, domain):
        """Query crt.sh for subdomains via Certificate Transparency logs."""
        try:
            from urllib.request import urlopen, Request
            import json as _json

            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            req = Request(url, headers={"User-Agent": "ATOMIC-Framework/10.0"})
            with urlopen(req, timeout=15) as resp:
                data = _json.loads(resp.read().decode("utf-8", errors="replace"))

            subdomains = set()
            for entry in data:
                name = entry.get("name_value", "")
                for line in name.split("\n"):
                    line = line.strip().lower()
                    if line and "*" not in line and domain in line:
                        subdomains.add(line)

            if subdomains:
                print(f"{Colors.info(f'Certificate Transparency: {len(subdomains)} subdomains found')}")
                for sub in sorted(subdomains)[:20]:
                    print(f"  - {sub}")
                from core.engine import Finding

                finding = Finding(
                    technique="Recon (Certificate Transparency)",
                    url=f"https://{domain}",
                    severity="INFO",
                    confidence=0.9,
                    param="N/A",
                    payload=f"{len(subdomains)} subdomains",
                    evidence=f"CT subdomains: {', '.join(sorted(subdomains)[:10])}",
                )
                self.engine.add_finding(finding)
            else:
                if self.verbose:
                    print(f"{Colors.info('CT: no subdomains found')}")
        except Exception as e:
            if self.verbose:
                print(f"{Colors.warning(f'CT lookup error: {e}')}")

    # ─── DNS Zone Transfer ──────────────────────────────────────────

    def _dns_zone_transfer(self, domain):
        """Attempt DNS zone transfer (AXFR) on discovered nameservers."""
        try:
            import dns.resolver
            import dns.zone
            import dns.query
        except ImportError:
            if self.verbose:
                print(f"{Colors.info('dnspython not installed — skipping zone transfer')}")
            return

        try:
            ns_records = dns.resolver.resolve(domain, "NS")
            nameservers = [str(rdata.target).rstrip(".") for rdata in ns_records]
        except Exception:
            return

        for ns in nameservers:
            try:
                ns_ip = socket.gethostbyname(ns)
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10))
                records = []
                for name, node in zone.nodes.items():
                    for rdataset in node.rdatasets:
                        for rdata in rdataset:
                            records.append(f"{name}.{domain} {rdataset.rdtype.name} {rdata}")

                if records:
                    print(f"{Colors.success(f'DNS Zone Transfer SUCCESSFUL on {ns}!')}")
                    for rec in records[:20]:
                        print(f"  {rec}")

                    from core.engine import Finding

                    finding = Finding(
                        technique="Recon (DNS Zone Transfer)",
                        url=f"dns://{ns}",
                        severity="HIGH",
                        confidence=0.95,
                        param="AXFR",
                        payload=ns,
                        evidence=f"Zone transfer from {ns}: {len(records)} records. "
                        f"Sample: {'; '.join(records[:5])}",
                    )
                    self.engine.add_finding(finding)
                    return  # One successful transfer is enough
            except Exception:
                continue

    # ─── WHOIS parsing ──────────────────────────────────────────────

    @staticmethod
    def _parse_whois(raw: str) -> Dict[str, str]:
        """Extract key fields from raw WHOIS output."""
        parsed: Dict[str, str] = {}
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("%") or line.startswith("#"):
                continue
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
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

    # ─── Email Security (SPF / DMARC / DKIM / BIMI) ────────────────

    def _check_email_security(self, domain: str):
        """Check SPF, DMARC, DKIM, and BIMI DNS records for email security posture."""
        try:
            import dns.resolver
        except ImportError:
            if self.verbose:
                print(f"{Colors.info('dnspython not installed — skipping email security check')}")
            return

        records_found = {}

        # SPF record (TXT on base domain)
        try:
            answers = dns.resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt = str(rdata).strip('"')
                if "v=spf1" in txt.lower():
                    records_found["SPF"] = txt[:200]
                    # Check for overly permissive SPF — match ' +all' or end with '+all'
                    if " +all" in txt or txt.strip().endswith("+all"):
                        from core.engine import Finding

                        finding = Finding(
                            technique="Recon (Weak SPF: +all)",
                            url=f"dns://{domain}",
                            severity="HIGH",
                            confidence=0.95,
                            param="SPF",
                            payload=txt[:100],
                            evidence=f"SPF record uses +all which allows ANY server to send email for {domain}",
                        )
                        self.engine.add_finding(finding)
        except Exception:
            pass

        # DMARC record (TXT on _dmarc.domain)
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            for rdata in answers:
                txt = str(rdata).strip('"')
                if "v=dmarc1" in txt.lower():
                    records_found["DMARC"] = txt[:200]
                    if "p=none" in txt.lower():
                        from core.engine import Finding

                        finding = Finding(
                            technique="Recon (Weak DMARC: p=none)",
                            url=f"dns://{domain}",
                            severity="MEDIUM",
                            confidence=0.9,
                            param="DMARC",
                            payload=txt[:100],
                            evidence=f"DMARC policy is 'none' — emails failing auth are still delivered",
                        )
                        self.engine.add_finding(finding)
        except Exception:
            pass

        # BIMI record (TXT on default._bimi.domain)
        try:
            answers = dns.resolver.resolve(f"default._bimi.{domain}", "TXT")
            for rdata in answers:
                txt = str(rdata).strip('"')
                if "v=bimi1" in txt.lower():
                    records_found["BIMI"] = txt[:200]
        except Exception:
            pass

        if records_found:
            print(f"{Colors.info('Email Security Records:')}")
            for rtype, value in records_found.items():
                print(f"  {rtype}: {value[:120]}")
        else:
            if self.verbose:
                print(f"{Colors.info('No SPF/DMARC/BIMI records found')}")

        # Report if key records are missing
        missing = []
        if "SPF" not in records_found:
            missing.append("SPF")
        if "DMARC" not in records_found:
            missing.append("DMARC")

        if missing:
            from core.engine import Finding

            finding = Finding(
                technique="Recon (Missing Email Auth Records)",
                url=f"dns://{domain}",
                severity="MEDIUM" if len(missing) >= 2 else "LOW",
                confidence=0.85,
                param="DNS",
                payload=", ".join(missing),
                evidence=f"Missing email authentication records: {', '.join(missing)}",
            )
            self.engine.add_finding(finding)

    # ─── HTTP/2 and ALPN Detection ──────────────────────────────────

    def _detect_http2_alpn(self, domain: str):
        """Detect HTTP/2 and ALPN protocol support via TLS handshake."""
        import ssl
        import socket as _socket

        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2", "http/1.1"])

            with _socket.create_connection((domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    negotiated = ssock.selected_alpn_protocol()
                    tls_version = ssock.version()

                    protocols = []
                    if negotiated:
                        protocols.append(f"ALPN: {negotiated}")
                    if tls_version:
                        protocols.append(f"TLS: {tls_version}")

                    if protocols:
                        print(f"{Colors.info(f'Protocol support: {', '.join(protocols)}')}")

                    # Flag old TLS versions
                    if tls_version and tls_version in ("TLSv1", "TLSv1.1"):
                        from core.engine import Finding

                        finding = Finding(
                            technique="Recon (Deprecated TLS Version)",
                            url=f"https://{domain}",
                            severity="MEDIUM",
                            confidence=0.95,
                            param="TLS",
                            payload=tls_version,
                            evidence=f"Server negotiated deprecated {tls_version} — vulnerable to known attacks",
                        )
                        self.engine.add_finding(finding)
        except Exception as e:
            if self.verbose:
                print(f"{Colors.warning(f'HTTP/2 / ALPN detection error: {e}')}")

    # ─── CMS Version Detection ──────────────────────────────────────

    def _detect_cms_version(self, url: str):
        """Detect CMS type and version from common version-disclosure endpoints."""
        version_checks = [
            # WordPress
            {
                "path": "/wp-login.php",
                "pattern": r'ver=([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
                "cms": "WordPress",
            },
            {
                "path": "/readme.html",
                "pattern": r'Version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
                "cms": "WordPress",
            },
            {
                "path": "/wp-includes/js/wp-emoji-release.min.js",
                "pattern": r'ver=([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
                "cms": "WordPress",
            },
            # Joomla
            {
                "path": "/administrator/manifests/files/joomla.xml",
                "pattern": r'<version>([0-9]+\.[0-9]+(?:\.[0-9]+)?)</version>',
                "cms": "Joomla",
            },
            # Drupal
            {
                "path": "/CHANGELOG.txt",
                "pattern": r'Drupal\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
                "cms": "Drupal",
            },
            {
                "path": "/core/CHANGELOG.txt",
                "pattern": r'Drupal\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
                "cms": "Drupal",
            },
        ]

        base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

        for check in version_checks:
            try:
                test_url = f"{base_url}{check['path']}"
                resp = self.requester.request(test_url, "GET")
                if resp and resp.status_code == 200 and resp.text:
                    match = re.search(check["pattern"], resp.text)
                    if match:
                        version = match.group(1)
                        print(f"{Colors.info(f'CMS Detected: {check['cms']} v{version}')}")
                        from core.engine import Finding

                        finding = Finding(
                            technique=f"Recon (CMS Version: {check['cms']})",
                            url=test_url,
                            severity="LOW",
                            confidence=0.9,
                            param="Version",
                            payload=f"{check['cms']} {version}",
                            evidence=f"{check['cms']} version {version} detected at {check['path']}",
                        )
                        self.engine.add_finding(finding)
                        return  # One CMS detection is enough
            except Exception:
                continue

    # ─── CORS Preflight Check ───────────────────────────────────────

    def _cors_preflight_check(self, url: str):
        """Send an OPTIONS preflight request and analyze CORS headers.

        Reports findings if the server allows overly broad origins,
        credentials, or dangerous methods via CORS.
        """
        try:
            resp = self.requester.request(url, "OPTIONS")
            if not resp:
                return
            headers = resp.headers
        except Exception as e:
            if self.verbose:
                print(f"{Colors.warning(f'CORS preflight error: {e}')}")
            return

        acao = headers.get("Access-Control-Allow-Origin", "")
        acac = headers.get("Access-Control-Allow-Credentials", "").lower()
        acam = headers.get("Access-Control-Allow-Methods", "")
        acah = headers.get("Access-Control-Allow-Headers", "")

        issues = []

        if acao == "*" and acac == "true":
            issues.append("Wildcard origin with credentials allowed")
        elif "evil-attacker.com" in acao:
            issues.append(f"Reflects arbitrary origin: {acao}")

        dangerous_methods = {"PUT", "DELETE", "PATCH"}
        if acam:
            allowed_set = {m.strip().upper() for m in acam.split(",")}
            dangerous_found = allowed_set & dangerous_methods
            if dangerous_found:
                issues.append(f"Dangerous methods allowed: {', '.join(dangerous_found)}")

        if issues:
            from core.engine import Finding

            severity = "HIGH" if "credential" in str(issues).lower() or "reflects" in str(issues).lower() else "MEDIUM"
            finding = Finding(
                technique="Recon (CORS Preflight Analysis)",
                url=url,
                severity=severity,
                confidence=0.85,
                param="CORS",
                payload="OPTIONS preflight",
                evidence=f"CORS issues: {'; '.join(issues)}. "
                f"ACAO={acao}, ACAC={acac}, ACAM={acam[:80]}",
            )
            self.engine.add_finding(finding)

        if acao or acam:
            print(f"{Colors.info(f'CORS: ACAO={acao or 'none'}, Methods={acam or 'none'}')}")
        elif self.verbose:
            print(f"{Colors.info('CORS: no CORS headers in preflight response')}")

    # ─── Wildcard DNS Detection ─────────────────────────────────────

    def _detect_wildcard_dns(self, domain):
        """Detect wildcard DNS to avoid false positives in subdomain enumeration.

        Resolves several randomly generated subdomain names. If they all
        resolve to the same IP address the domain very likely has a DNS
        wildcard record.  The finding is informational but important for
        downstream subdomain enumeration accuracy.
        """
        _RANDOM_LABELS = 3
        resolved_ips: Dict[str, str] = {}

        for _ in range(_RANDOM_LABELS):
            label = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
            fqdn = f"{label}.{domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                resolved_ips[fqdn] = ip
            except socket.gaierror:
                pass

        if len(resolved_ips) >= 2:
            unique_ips = set(resolved_ips.values())
            if len(unique_ips) == 1:
                wildcard_ip = unique_ips.pop()
                print(f"{Colors.warning(f'Wildcard DNS detected: *.{domain} → {wildcard_ip}')}")
                from core.engine import Finding

                finding = Finding(
                    technique="Recon (Wildcard DNS Detection)",
                    url=f"https://{domain}",
                    severity="INFO",
                    confidence=0.95,
                    param="DNS",
                    payload=f"*.{domain} → {wildcard_ip}",
                    evidence=f"Random subdomains resolve to {wildcard_ip}: "
                    f"{', '.join(resolved_ips.keys())}",
                )
                self.engine.add_finding(finding)
                return True
        elif self.verbose:
            print(f"{Colors.info('Wildcard DNS: not detected')}")
        return False

    # ─── VHost Discovery ────────────────────────────────────────────

    def _discover_vhosts(self, target, domain):
        """Discover virtual hosts by fuzzing the Host header.

        Sends HTTP requests to the target IP with different Host header
        values.  Responses that differ significantly from the baseline
        (different status code or substantially different content length)
        indicate a distinct virtual host.
        """
        vhost_wordlist = [
            "www", "mail", "remote", "vpn", "dev", "staging", "api",
            "admin", "cdn", "static", "assets", "jenkins", "gitlab",
            "jira", "confluence", "test", "uat", "prod", "backup",
            "portal", "intranet", "internal", "beta", "alpha", "demo",
            "docs", "wiki", "support", "helpdesk", "monitor", "grafana",
            "kibana", "elastic", "prometheus", "ci", "cd", "build",
        ]

        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Get baseline response for the known host
        try:
            baseline_resp = self.requester.request(base_url, "GET")
            if not baseline_resp:
                return
            baseline_status = baseline_resp.status_code
            baseline_length = len(baseline_resp.text) if baseline_resp.text else 0
        except Exception:
            return

        discovered_vhosts = []

        for vhost_name in vhost_wordlist:
            fqdn = f"{vhost_name}.{domain}"
            try:
                resp = self.requester.request(
                    base_url, "GET", headers={"Host": fqdn}
                )
                if not resp:
                    continue

                resp_length = len(resp.text) if resp.text else 0
                status = resp.status_code

                # A different status or significantly different body length
                # indicates a real virtual host
                length_diff = abs(resp_length - baseline_length)
                length_threshold = max(100, baseline_length * 0.1)

                if (
                    status != baseline_status
                    or length_diff > length_threshold
                ) and status != 400:
                    discovered_vhosts.append(
                        {
                            "host": fqdn,
                            "status": status,
                            "length": resp_length,
                        }
                    )
            except Exception:
                continue

        if discovered_vhosts:
            from core.engine import Finding

            hosts_str = ", ".join(
                f"{v['host']} ({v['status']}, {v['length']}B)"
                for v in discovered_vhosts[:10]
            )
            print(f"{Colors.success(f'VHost discovery: {len(discovered_vhosts)} virtual hosts found')}")
            finding = Finding(
                technique="Recon (Virtual Host Discovery)",
                url=target,
                severity="INFO",
                confidence=0.7,
                param="Host header",
                payload=f"{len(discovered_vhosts)} virtual hosts",
                evidence=f"Discovered VHosts: {hosts_str}",
            )
            self.engine.add_finding(finding)
        elif self.verbose:
            print(f"{Colors.info('VHost discovery: no additional virtual hosts found')}")
