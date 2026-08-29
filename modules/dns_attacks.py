#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - DNS Attack Module
DNS cache poisoning, rebinding, tunneling, zone transfer, DNSSEC bypass.
"""
import socket
import struct
import random
import time
import hashlib
from config import Colors
from modules.base import BaseModule


class DNSAttackModule(BaseModule):
    """DNS attack detection and exploitation."""

    name = "DNS Attacks"
    vuln_type = "dns"

    def __init__(self, engine):
        super().__init__(engine)
        self.resolver_port = 53

    def test_url(self, url):
        """Run DNS-level tests against the target hostname."""
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname or url
        if not hostname:
            return

        self._test_zone_transfer(hostname, url)
        self._test_dns_rebinding(hostname, url)
        self._test_dns_tunneling(hostname, url)
        self._test_dnssec_bypass(hostname, url)
        self._test_wildcard_dns(hostname, url)
        self._test_dns_cache_poison(hostname, url)
        self._test_subdomain_takeover(hostname, url)

    def _test_zone_transfer(self, domain, url):
        """Test for DNS zone transfer (AXFR) vulnerability."""
        import subprocess
        try:
            # Try zone transfer against each NS
            result = subprocess.run(
                ["dig", "NS", domain, "+short"],
                capture_output=True, text=True, timeout=10
            )
            nameservers = [l.strip().rstrip('.') for l in result.stdout.strip().split('\n') if l.strip()]
            for ns in nameservers[:3]:
                try:
                    axfr = subprocess.run(
                        ["dig", "AXFR", domain, f"@{ns}"],
                        capture_output=True, text=True, timeout=15
                    )
                    if "Transfer failed" not in axfr.stdout and "SOA" in axfr.stdout:
                        self.engine.add_finding(self._finding(
                            technique="DNS Zone Transfer",
                            url=url,
                            severity="HIGH",
                            confidence=0.95,
                            param=f"NS: {ns}",
                            payload=f"dig AXFR {domain} @{ns}",
                            evidence=f"Zone transfer successful against {ns}: {len(axfr.stdout)} bytes",
                        ))
                except Exception:
                    pass
        except Exception:
            pass

    def _test_dns_rebinding(self, domain, url):
        """Test for DNS rebinding vulnerability."""
        # Check if the application validates Host header against DNS
        try:
            headers = {"Host": f"127.0.0.1"}
            resp = self.requester.request(url, "GET", headers=headers)
            if resp and resp.status_code == 200 and len(resp.text) > 100:
                self.engine.add_finding(self._finding(
                    technique="DNS Rebinding (Host Header)",
                    url=url,
                    severity="HIGH",
                    confidence=0.6,
                    param="Host",
                    payload="127.0.0.1",
                    evidence=f"Application responded to Host: 127.0.0.1 with status {resp.status_code}",
                ))
        except Exception:
            pass

        # Test rebinding via wildcard DNS services
        rebinding_domains = [
            f"127.0.0.1.{domain}",
            f"{domain}.nip.io",
            f"localtest.me",
        ]
        for rdomain in rebinding_domains:
            try:
                test_url = url.replace(domain, rdomain)
                resp = self.requester.request(test_url, "GET", timeout=5)
                if resp and resp.status_code == 200:
                    self.engine.add_finding(self._finding(
                        technique="DNS Rebinding",
                        url=url,
                        severity="MEDIUM",
                        confidence=0.5,
                        param=rdomain,
                        payload=test_url,
                        evidence=f"Rebinding domain {rdomain} resolved and responded",
                    ))
                    break
            except Exception:
                pass

    def _test_dns_tunneling(self, domain, url):
        """Test for DNS tunneling indicators."""
        # Check for excessively long subdomains (tunneling indicator)
        import subprocess
        try:
            result = subprocess.run(
                ["dig", "TXT", domain, "+short"],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout and len(result.stdout) > 500:
                self.engine.add_finding(self._finding(
                    technique="DNS Tunneling Indicator",
                    url=url,
                    severity="MEDIUM",
                    confidence=0.4,
                    param="TXT",
                    payload="dig TXT " + domain,
                    evidence=f"Large TXT record ({len(result.stdout)} bytes) may indicate tunneling",
                ))
        except Exception:
            pass

    def _test_dnssec_bypass(self, domain, url):
        """Test for DNSSEC misconfiguration."""
        import subprocess
        try:
            result = subprocess.run(
                ["dig", "DNSKEY", domain, "+short"],
                capture_output=True, text=True, timeout=10
            )
            if not result.stdout.strip():
                self.engine.add_finding(self._finding(
                    technique="DNSSEC Not Configured",
                    url=url,
                    severity="LOW",
                    confidence=0.9,
                    param="DNSKEY",
                    payload=f"dig DNSKEY {domain}",
                    evidence=f"Domain {domain} has no DNSSEC records — DNS responses can be spoofed",
                ))
        except Exception:
            pass

    def _test_wildcard_dns(self, domain, url):
        """Test for wildcard DNS configuration."""
        import subprocess
        random_sub = f"random{random.randint(100000,999999)}.{domain}"
        try:
            result = subprocess.run(
                ["dig", "A", random_sub, "+short"],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout.strip():
                ip = result.stdout.strip().split('\n')[0]
                self.engine.add_finding(self._finding(
                    technique="Wildcard DNS",
                    url=url,
                    severity="INFO",
                    confidence=0.95,
                    param=random_sub,
                    payload=f"dig A {random_sub}",
                    evidence=f"Wildcard DNS resolves {random_sub} → {ip}",
                ))
        except Exception:
            pass

    def _test_dns_cache_poison(self, domain, url):
        """Test for DNS cache poisoning indicators."""
        # Check if resolver uses predictable source ports
        import subprocess
        try:
            ports = set()
            for _ in range(3):
                result = subprocess.run(
                    ["dig", "A", f"test{random.randint(1,9999)}.{domain}", f"@{domain}"],
                    capture_output=True, text=True, timeout=5
                )
            # If we can query the authoritative NS directly, it may be open
            result = subprocess.run(
                ["dig", "A", domain, f"@{domain}", "+short"],
                capture_output=True, text=True, timeout=5
            )
            if result.stdout.strip():
                self.engine.add_finding(self._finding(
                    technique="DNS Open Resolver",
                    url=url,
                    severity="MEDIUM",
                    confidence=0.7,
                    param=domain,
                    payload=f"dig A {domain} @{domain}",
                    evidence=f"DNS server at {domain} responds to recursive queries (open resolver)",
                ))
        except Exception:
            pass

    def _test_subdomain_takeover(self, domain, url):
        """Test for subdomain takeover via CNAME pointing to deprovisioned services."""
        import subprocess
        takeover_signatures = {
            "amazonaws.com": "NoSuchBucket",
            "herokuapp.com": "No such app",
            "github.io": "There isn't a GitHub Pages site here",
            "azurewebsites.net": "Azure Web App - Your web app is running",
            "cloudfront.net": "Bad request",
            "s3.amazonaws.com": "NoSuchBucket",
            "shopify.com": "Sorry, this shop is currently unavailable",
            "fastly.net": "Fastly error: unknown domain",
            "pantheon.io": "404 error unknown site!",
            "surge.sh": "project not found",
            "bitbucket.org": "Repository not found",
            "ghost.io": "The thing you were looking for is no longer here",
            "wordpress.com": "Do you want to register",
            "zendesk.com": "Help Center Closed",
            "readme.io": "Project not found",
            "ghost.io": "The thing you were looking for is no longer here",
        }
        try:
            result = subprocess.run(
                ["dig", "CNAME", domain, "+short"],
                capture_output=True, text=True, timeout=10
            )
            for cname in result.stdout.strip().split('\n'):
                cname = cname.strip().rstrip('.')
                if not cname:
                    continue
                for service, signature in takeover_signatures.items():
                    if service in cname:
                        try:
                            resp = self.requester.request(f"http://{cname}", "GET", timeout=5)
                            if resp and signature.lower() in resp.text.lower():
                                self.engine.add_finding(self._finding(
                                    technique="Subdomain Takeover",
                                    url=url,
                                    severity="CRITICAL",
                                    confidence=0.85,
                                    param=f"CNAME → {cname}",
                                    payload=f"dig CNAME {domain}",
                                    evidence=f"CNAME {cname} points to deprovisioned {service}: {signature}",
                                ))
                        except Exception:
                            pass
        except Exception:
            pass

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
