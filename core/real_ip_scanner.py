#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v9.0 - ULTIMATE EDITION
Phase 2 — Real IP / Origin Discovery

Multi-track approach:
  Track A  Passive intelligence (cert transparency, SPF/MX, ASN)
  Track B  Subdomain-based IP triage
  Track C  Active probing (HTTP host-header, port scan) — fallback only

Candidate IPs are scored and the top candidate is verified.
"""

import hashlib
import ipaddress
import re
import socket
import ssl
from urllib.parse import urlparse

from config import Colors
from core.engine import Finding

# ── CDN CIDRs (re-used for triage) ────────────────────────────────────
CDN_CIDRS = {
    "Cloudflare": [
        "103.21.244.0/22",
        "104.16.0.0/13",
        "172.64.0.0/13",
        "198.41.128.0/17",
    ],
    "Akamai": ["23.32.0.0/11", "2.16.0.0/13"],
    "Fastly": ["151.101.0.0/16", "199.27.72.0/21"],
    "CloudFront": ["13.32.0.0/15", "54.182.0.0/16"],
    "Sucuri": ["192.88.134.0/23", "185.93.228.0/22"],
}


def _build_cdn_networks():
    nets = []
    for cidrs in CDN_CIDRS.values():
        for cidr in cidrs:
            try:
                nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass
    return nets


_CDN_NETS = _build_cdn_networks()


def _is_cdn_ip(ip_str):
    """Return True if *ip_str* falls inside any known CDN CIDR."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in _CDN_NETS)
    except ValueError:
        return False


def _mmh3_hash(data: bytes) -> int:
    """Minimal MurmurHash3-32 (no external deps)."""
    h = hashlib.md5(data).hexdigest()  # fallback pseudo-hash
    return int(h[:8], 16)


# Subdomain wordlist for brute-force
SUBDOMAIN_WORDLIST = [
    "direct",
    "origin",
    "origin-www",
    "mail",
    "ftp",
    "vpn",
    "dev",
    "staging",
    "api",
    "admin",
    "old",
    "beta",
    "test",
    "internal",
    "backend",
    "gateway",
    "proxy",
    "ns1",
    "ns2",
    "mx",
    "smtp",
    "pop",
    "imap",
    "webmail",
    "cpanel",
    "whm",
    "ssh",
    "git",
    "ci",
    "jenkins",
    "monitor",
    "grafana",
]


class RealIPScanner:
    """Phase 2 — discover origin IP behind CDN."""

    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.verbose = engine.config.get("verbose", False)
        self._target_fingerprint = None  # (title, body_hash)

    # ── public API ────────────────────────────────────────────────────

    def run(self, target: str, shield_profile=None) -> dict:
        """Execute all tracks, rank, verify, and return RealIPResult."""
        print(f"\n{Colors.info('Phase 2: Real IP / Origin Discovery...')}")
        self.engine.emit_pipeline_event("realip_start", {"target": target})

        domain = self._extract_domain(target)
        if not domain:
            return self._empty_result()

        # Fingerprint target for later verification
        self._fingerprint_target(target)

        candidates = []

        # Track A — passive intel
        candidates += self._check_spf_mx(domain)
        candidates += self._check_certificate_intel(domain)
        candidates += self._check_historical_dns(domain)

        # Track B — subdomain intel
        subs_passive = self._enumerate_subdomains_passive(domain)
        subs_active = self._enumerate_subdomains_active(domain)
        all_subs = list(set(subs_passive + subs_active))
        candidates += self._triage_subdomain_ips(all_subs)

        # Zone transfer (rare but valuable)
        zt_subs = self._check_zone_transfer(domain)
        if zt_subs:
            candidates += self._triage_subdomain_ips(zt_subs)

        # De-duplicate
        seen = set()
        unique = []
        for c in candidates:
            if c["ip"] not in seen:
                seen.add(c["ip"])
                unique.append(c)
        candidates = unique

        # Rank
        ranked = self._rank_candidates(candidates)

        # Track C — verify top candidates
        origin_ip = None
        confidence = "LOW"
        method = ""
        verified = False

        for cand in ranked[:10]:
            ok = self._verify_origin(cand["ip"], domain)
            if ok:
                origin_ip = cand["ip"]
                method = cand.get("source", "unknown")
                verified = True
                if cand["score"] >= 50:
                    confidence = "HIGH"
                elif cand["score"] >= 30:
                    confidence = "MEDIUM"
                break

        if not verified and ranked:
            # Best guess
            origin_ip = ranked[0]["ip"]
            method = ranked[0].get("source", "unknown")
            confidence = "LOW"

        result = {
            "origin_ip": origin_ip,
            "confidence": confidence,
            "method": method,
            "verified": verified,
            "all_candidates": ranked[:20],
        }

        self._print_summary(result)
        self._emit_findings(target, result)
        self.engine.emit_pipeline_event(
            "realip_done",
            {
                "origin_ip": origin_ip,
                "confidence": confidence,
            },
        )
        return result

    # ── Track A — passive intel ───────────────────────────────────────

    def _check_historical_dns(self, domain):
        """Query crt.sh for certificate transparency entries."""
        candidates = []
        try:
            resp = self.requester.request(
                f"https://crt.sh/?q=%.{domain}&output=json",
                "GET",
                timeout=10,
            )
            if resp and resp.status_code == 200:
                data = resp.json()
                for entry in data[:100]:
                    name = entry.get("common_name", "") or entry.get("name_value", "")
                    # crt.sh doesn't give IPs directly, but we can track
                    # unique names for subdomain enumeration
                    if name and "*" not in name:
                        try:
                            ips = socket.gethostbyname_ex(name)[2]
                            for ip in ips:
                                if not _is_cdn_ip(ip):
                                    candidates.append(
                                        {
                                            "ip": ip,
                                            "score": 30,
                                            "source": "historical_dns",
                                        }
                                    )
                        except (socket.gaierror, OSError):
                            pass
        except Exception as e:
            if self.verbose:
                print(f"  {Colors.warning(f'crt.sh query failed: {e}')}")
        return candidates

    def _check_certificate_intel(self, domain):
        """Extract IPs from target's TLS certificate SANs."""
        candidates = []
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            # Enforce minimum TLS 1.2 for security
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if cert:
                        # Check SANs for IP addresses
                        sans = cert.get("subjectAltName", ())
                        for san_type, san_val in sans:
                            if san_type == "IP Address":
                                if not _is_cdn_ip(san_val):
                                    candidates.append(
                                        {
                                            "ip": san_val,
                                            "score": 50,
                                            "source": "cert_match",
                                        }
                                    )
        except Exception as e:
            if self.verbose:
                print(f"  {Colors.warning(f'Cert intel error: {e}')}")
        return candidates

    def _check_favicon_hash(self, target_url):
        """Fetch /favicon.ico and compute hash for matching."""
        result = {"hash": None, "candidates": []}
        try:
            resp = self.requester.request(f"{target_url}/favicon.ico", "GET", timeout=10)
            if resp and resp.status_code == 200 and resp.content:
                result["hash"] = _mmh3_hash(resp.content)
        except Exception:
            pass
        return result

    def _check_spf_mx(self, domain):
        """Parse SPF ip4: entries and resolve MX records."""
        candidates = []

        # SPF records
        try:
            import dns.resolver

            try:
                answers = dns.resolver.resolve(domain, "TXT")
                for rdata in answers:
                    txt = str(rdata).strip('"')
                    if "v=spf1" in txt:
                        for part in txt.split():
                            if part.startswith("ip4:"):
                                ip_str = part[4:].split("/")[0]
                                if not _is_cdn_ip(ip_str):
                                    candidates.append(
                                        {
                                            "ip": ip_str,
                                            "score": 25,
                                            "source": "spf_record",
                                        }
                                    )
            except Exception:
                pass

            # MX records → resolve to IPs
            try:
                mx_answers = dns.resolver.resolve(domain, "MX")
                for rdata in mx_answers:
                    mx_host = str(rdata.exchange).rstrip(".")
                    try:
                        ips = socket.gethostbyname_ex(mx_host)[2]
                        for ip in ips:
                            if not _is_cdn_ip(ip):
                                candidates.append(
                                    {
                                        "ip": ip,
                                        "score": 25,
                                        "source": "mx_record",
                                    }
                                )
                    except (socket.gaierror, OSError):
                        pass
            except Exception:
                pass
        except ImportError:
            pass  # dnspython not available

        return candidates

    def _check_asn_info(self, domain):
        """WHOIS / ASN correlation — limited passive check."""
        candidates = []
        try:
            ips = socket.gethostbyname_ex(domain)[2]
            for ip in ips:
                if not _is_cdn_ip(ip):
                    candidates.append(
                        {
                            "ip": ip,
                            "score": 20,
                            "source": "asn_correlation",
                        }
                    )
        except (socket.gaierror, OSError):
            pass
        return candidates

    # ── Track B — subdomain intel ─────────────────────────────────────

    def _enumerate_subdomains_passive(self, domain):
        """Use crt.sh for passive subdomain enumeration."""
        subs = set()
        try:
            resp = self.requester.request(
                f"https://crt.sh/?q=%.{domain}&output=json",
                "GET",
                timeout=10,
            )
            if resp and resp.status_code == 200:
                for entry in resp.json()[:200]:
                    name = entry.get("name_value", "")
                    for line in name.split("\n"):
                        line = line.strip().lstrip("*.")
                        if line.endswith(domain) and line != domain:
                            subs.add(line)
        except Exception:
            pass
        return list(subs)

    def _enumerate_subdomains_active(self, domain):
        """Brute-force common subdomains."""
        found = []
        # Wildcard detection
        wildcard_ip = None
        try:
            wildcard_ip = socket.gethostbyname(f"randomxyz123notexist.{domain}")
        except (socket.gaierror, OSError):
            pass

        for word in SUBDOMAIN_WORDLIST:
            sub = f"{word}.{domain}"
            try:
                ip = socket.gethostbyname(sub)
                if ip != wildcard_ip:
                    found.append(sub)
            except (socket.gaierror, OSError):
                pass
        return found

    def _check_zone_transfer(self, domain):
        """Attempt AXFR zone transfer (very rarely works)."""
        results = []
        try:
            import dns.resolver
            import dns.zone
            import dns.query

            ns_answers = dns.resolver.resolve(domain, "NS")
            for ns in ns_answers:
                ns_host = str(ns.target).rstrip(".")
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, timeout=10))
                    for name, node in zone.nodes.items():
                        fqdn = f"{name}.{domain}".rstrip(".")
                        if fqdn != domain:
                            results.append(fqdn)
                    if results and self.verbose:
                        print(f"  {Colors.critical(f'Zone transfer succeeded on {ns_host}!')}")
                    break
                except Exception:
                    pass
        except (ImportError, Exception):
            pass
        return results

    def _triage_subdomain_ips(self, subdomains):
        """Resolve subdomains → IPs, discard CDN IPs."""
        candidates = []
        HIGH_VALUE = {"mail", "ftp", "vpn", "ssh", "direct", "origin", "backend"}
        for sub in subdomains:
            try:
                ips = socket.gethostbyname_ex(sub)[2]
                for ip in ips:
                    if not _is_cdn_ip(ip):
                        prefix = sub.split(".")[0]
                        score = 30 if prefix in HIGH_VALUE else 20
                        candidates.append(
                            {
                                "ip": ip,
                                "score": score,
                                "source": f"subdomain:{sub}",
                            }
                        )
            except (socket.gaierror, OSError):
                pass
        return candidates

    # ── Track C — active probing ──────────────────────────────────────

    def _verify_origin(self, ip: str, domain: str) -> bool:
        """HTTP probe candidate IP with Host header matching."""
        for port in (443, 80, 8443, 8080):
            try:
                scheme = "https" if port in (443, 8443) else "http"
                url = f"{scheme}://{ip}:{port}/"
                resp = self.requester.request(
                    url,
                    "GET",
                    headers={"Host": domain},
                    timeout=8,
                    allow_redirects=False,
                )
                if resp and resp.status_code < 500:
                    # Check body fingerprint
                    if self._target_fingerprint:
                        title, body_hash = self._target_fingerprint
                        resp_title = self._extract_title(resp.text) if hasattr(resp, "text") else ""
                        if title and resp_title and title.lower() == resp_title.lower():
                            return True
                        resp_hash = (
                            hashlib.md5(resp.text.encode("utf-8", "ignore")).hexdigest()
                            if hasattr(resp, "text")
                            else ""
                        )
                        if body_hash and resp_hash == body_hash:
                            return True
                    # Fallback: 2xx or 3xx is a positive signal
                    if resp.status_code < 400:
                        return True
            except Exception:
                pass
        return False

    def _port_scan_candidates(self, candidate_ips, ports=None):
        """Quick TCP connect scan on candidate IPs."""
        if ports is None:
            ports = [80, 443, 8080, 8443, 8888, 9000]
        open_ips = []
        for ip in candidate_ips[:20]:
            for port in ports:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(3)
                    if s.connect_ex((ip, port)) == 0:
                        open_ips.append({"ip": ip, "port": port})
                    s.close()
                except Exception:
                    pass
        return open_ips

    # ── scoring ───────────────────────────────────────────────────────

    def _rank_candidates(self, candidates):
        """Aggregate scores per IP and sort descending."""
        scores = {}
        for c in candidates:
            ip = c["ip"]
            if ip not in scores:
                scores[ip] = {"ip": ip, "score": 0, "sources": []}
            scores[ip]["score"] += c.get("score", 0)
            scores[ip]["sources"].append(c.get("source", ""))
        ranked = sorted(scores.values(), key=lambda x: x["score"], reverse=True)
        return ranked

    # ── helpers ────────────────────────────────────────────────────────

    def _fingerprint_target(self, target_url):
        try:
            resp = self.requester.request(target_url, "GET", timeout=10)
            if resp and hasattr(resp, "text"):
                title = self._extract_title(resp.text)
                body_hash = hashlib.md5(resp.text.encode("utf-8", "ignore")).hexdigest()
                self._target_fingerprint = (title, body_hash)
        except Exception:
            self._target_fingerprint = None

    @staticmethod
    def _extract_title(html):
        match = re.search(r"<title[^>]*>(.*?)</title>", html or "", re.IGNORECASE | re.DOTALL)
        return match.group(1).strip() if match else ""

    @staticmethod
    def _extract_domain(target):
        return urlparse(target).hostname or ""

    def _empty_result(self):
        return {
            "origin_ip": None,
            "confidence": "LOW",
            "method": "",
            "verified": False,
            "all_candidates": [],
        }

    def _print_summary(self, result):
        print(f"\n  {Colors.BOLD}Real IP Discovery Summary:{Colors.RESET}")
        if result["origin_ip"]:
            v = "✓ verified" if result["verified"] else "? unverified"
            print(
                f"    Origin IP: {Colors.GREEN}{result['origin_ip']}{Colors.RESET}" f"  [{result['confidence']}] ({v})"
            )
            print(f"    Method: {result['method']}")
        else:
            print(f"    Origin IP: {Colors.YELLOW}Not found{Colors.RESET}")
        print(f"    Candidates evaluated: {len(result['all_candidates'])}")

    def _emit_findings(self, target, result):
        if result["origin_ip"] and result["verified"]:
            self.engine.add_finding(
                Finding(
                    technique="Origin IP Discovered",
                    url=target,
                    severity="HIGH",
                    confidence=0.85 if result["confidence"] == "HIGH" else 0.6,
                    evidence=f"Origin: {result['origin_ip']} via {result['method']}",
                    remediation="Restrict origin server to only accept traffic from CDN IPs. Use firewall ACLs.",
                )
            )
