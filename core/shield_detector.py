#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v9.0 - ULTIMATE EDITION
Phase 1 — Shield Detection (CDN + WAF fingerprinting)

Detects CDN providers (Cloudflare, Akamai, Fastly, CloudFront, Sucuri)
and WAF presence via DNS CNAME chains, IP-range CIDR matching, HTTP
header signatures, and adversarial probe payloads.

Returns a ShieldProfile dict consumed by downstream phases.
"""

import ipaddress
import socket
from urllib.parse import urlparse, urlencode, urljoin

from config import Colors
from core.engine import Finding

# ── CDN IP CIDR databases ─────────────────────────────────────────────
CDN_CIDRS = {
    'Cloudflare': [
        '103.21.244.0/22', '104.16.0.0/13', '172.64.0.0/13',
        '198.41.128.0/17', '131.0.72.0/22', '162.158.0.0/15',
        '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22',
        '173.245.48.0/20', '108.162.192.0/18',
    ],
    'Akamai': [
        '23.32.0.0/11', '2.16.0.0/13', '23.192.0.0/11',
        '104.64.0.0/10',
    ],
    'Fastly': [
        '151.101.0.0/16', '199.27.72.0/21', '23.235.32.0/20',
    ],
    'CloudFront': [
        '13.32.0.0/15', '54.182.0.0/16', '13.224.0.0/14',
        '52.84.0.0/15', '99.84.0.0/16', '143.204.0.0/16',
    ],
    'Sucuri': [
        '192.88.134.0/23', '185.93.228.0/22', '66.248.200.0/22',
    ],
}

# CNAME suffix → CDN name
CNAME_SIGNATURES = {
    '.cdn.cloudflare.net': 'Cloudflare',
    '.cloudflare.net': 'Cloudflare',
    '.akamaiedge.net': 'Akamai',
    '.akamai.net': 'Akamai',
    '.edgesuite.net': 'Akamai',
    '.fastly.net': 'Fastly',
    '.fastlylb.net': 'Fastly',
    '.cloudfront.net': 'CloudFront',
    '.sucuri.net': 'Sucuri',
    '.sucuridns.com': 'Sucuri',
    '.azureedge.net': 'Azure CDN',
    '.edgecastcdn.net': 'Verizon CDN',
    '.stackpathdns.com': 'StackPath',
    '.incapdns.net': 'Incapsula',
}

# Response header → CDN / WAF name
HEADER_SIGNATURES = {
    'cf-ray': 'Cloudflare',
    'cf-cache-status': 'Cloudflare',
    'x-amz-cf-id': 'CloudFront',
    'x-amz-cf-pop': 'CloudFront',
    'x-sucuri-id': 'Sucuri',
    'x-sucuri-cache': 'Sucuri',
    'x-akamai-transformed': 'Akamai',
}

# WAF probe payloads (innocuous but likely to trigger WAF rules)
WAF_PROBES = [
    '<script>alert(1)</script>',
    "' OR 1=1--",
    '../../etc/passwd',
    'SELECT * FROM users',
]

# Status/header combos that fingerprint specific WAFs
WAF_SIGNATURES = [
    # (status_check, header_key, header_value_pattern, body_pattern, waf_name)
    (403, 'cf-ray', None, None, 'Cloudflare WAF'),
    (403, 'server', 'cloudflare', None, 'Cloudflare WAF'),
    (406, None, None, 'Not Acceptable', 'ModSecurity'),
    (None, None, None, 'Request blocked', 'AWS WAF'),
    (None, None, None, 'Powered by Sucuri', 'Sucuri WAF'),
    (999, None, None, None, 'Nginx WAF (custom)'),
    (403, 'server', 'AkamaiGHost', None, 'Akamai WAF'),
    (403, None, None, 'Access Denied', 'Generic WAF'),
    (None, 'x-sucuri-block', None, None, 'Sucuri WAF'),
]


def _build_cdn_networks():
    """Pre-compile CIDR strings into ipaddress network objects."""
    nets = {}
    for provider, cidrs in CDN_CIDRS.items():
        nets[provider] = []
        for cidr in cidrs:
            try:
                nets[provider].append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass
    return nets


_CDN_NETS = _build_cdn_networks()


class ShieldDetector:
    """Phase 1 — CDN + WAF detection returning a *ShieldProfile* dict."""

    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.verbose = engine.config.get('verbose', False)

    # ── public API ────────────────────────────────────────────────────

    def run(self, target: str, probe_result=None) -> dict:
        """Run full shield detection and return ShieldProfile."""
        print(f"\n{Colors.info('Phase 1: Shield Detection (CDN + WAF)...')}")
        self.engine.emit_pipeline_event('shield_detect_start', {'target': target})

        cdn = self.detect_cdn(target, probe_result)
        waf = self.detect_waf(target)

        profile = {
            'cdn': cdn,
            'waf': waf,
            'needs_origin_discovery': cdn.get('detected', False),
            'needs_waf_bypass': waf.get('detected', False),
        }
        self._print_summary(profile)
        self._emit_findings(target, profile)
        self.engine.emit_pipeline_event('shield_detect_done', profile)
        return profile

    # ── CDN detection ─────────────────────────────────────────────────

    def detect_cdn(self, target: str, probe_result=None) -> dict:
        result = {
            'detected': False,
            'provider': None,
            'edge_ip': None,
            'cname_chain': [],
            'cidr_matched': None,
        }
        hostname = urlparse(target).hostname or ''
        if not hostname:
            return result

        # 1) DNS resolution — A records + CNAME chain
        ips, cnames = self._resolve_dns(hostname)
        result['cname_chain'] = cnames
        if ips:
            result['edge_ip'] = ips[0]

        # 2) CNAME-based detection
        for cname in cnames:
            for suffix, provider in CNAME_SIGNATURES.items():
                if cname.endswith(suffix):
                    result['detected'] = True
                    result['provider'] = provider
                    break
            if result['detected']:
                break

        # 3) IP CIDR match
        if not result['detected']:
            for ip_str in ips:
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    for provider, nets in _CDN_NETS.items():
                        for net in nets:
                            if ip_obj in net:
                                result['detected'] = True
                                result['provider'] = provider
                                result['cidr_matched'] = str(net)
                                break
                        if result['detected']:
                            break
                except ValueError:
                    continue
                if result['detected']:
                    break

        # 4) Header-based detection
        resp = None
        if probe_result and probe_result.get('response'):
            resp = probe_result['response']
        if resp is None:
            try:
                resp = self.requester.request(target, 'GET')
            except Exception:
                pass
        if resp and not result['detected']:
            result = self._check_cdn_headers(resp, result)

        if self.verbose:
            status = f"CDN detected: {result['provider']}" if result['detected'] else 'No CDN detected'
            print(f"  {Colors.info(status)}")

        return result

    # ── WAF detection ─────────────────────────────────────────────────

    def detect_waf(self, target: str) -> dict:
        result = {
            'detected': False,
            'provider': None,
            'confidence': 0.0,
            'block_code': None,
            'block_threshold': 0,
            'signatures_matched': [],
        }

        blocked_count = 0
        total_probes = len(WAF_PROBES)

        for payload in WAF_PROBES:
            try:
                probe_url = self._build_probe_url(target, payload)
                resp = self.requester.request(probe_url, 'GET')
                if resp is None:
                    continue

                status = resp.status_code
                headers = {k.lower(): v for k, v in resp.headers.items()}
                body = resp.text[:4096] if hasattr(resp, 'text') else ''

                match = self._match_waf_signature(status, headers, body)
                if match:
                    if not result['detected']:
                        result['detected'] = True
                        result['provider'] = match
                        result['block_code'] = status
                    if match not in result['signatures_matched']:
                        result['signatures_matched'].append(match)
                    blocked_count += 1
            except Exception as e:
                if self.verbose:
                    print(f"  {Colors.warning(f'WAF probe error: {e}')}")

        if blocked_count > 0:
            result['confidence'] = min(blocked_count / total_probes, 1.0)
            result['block_threshold'] = total_probes - blocked_count

        if self.verbose:
            if result['detected']:
                provider = result['provider']
                conf = result['confidence']
                print(f"  {Colors.warning(f'WAF detected: {provider} (confidence {conf:.0%})')}")
            else:
                print(f"  {Colors.info('No WAF detected')}")

        return result

    # ── helpers ────────────────────────────────────────────────────────

    def _resolve_dns(self, hostname: str):
        """Resolve hostname → (ip_list, cname_chain)."""
        ips = []
        cnames = []

        # Try dnspython first for CNAME chain
        try:
            import dns.resolver
            try:
                answers = dns.resolver.resolve(hostname, 'CNAME')
                for rdata in answers:
                    cnames.append(str(rdata.target).rstrip('.'))
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                pass
            except Exception:
                pass

            try:
                answers = dns.resolver.resolve(hostname, 'A')
                for rdata in answers:
                    ips.append(str(rdata.address))
            except Exception:
                pass
        except ImportError:
            pass

        # Fallback to socket
        if not ips:
            try:
                for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
                    ip = info[4][0]
                    if ip not in ips:
                        ips.append(ip)
            except (socket.gaierror, OSError):
                pass

        return ips, cnames

    def _check_cdn_headers(self, response, result: dict) -> dict:
        """Detect CDN from response headers."""
        if not hasattr(response, 'headers'):
            return result
        headers = {k.lower(): v for k, v in response.headers.items()}

        for header_key, provider in HEADER_SIGNATURES.items():
            if header_key in headers:
                result['detected'] = True
                result['provider'] = provider
                break

        # Server header heuristics
        server = headers.get('server', '').lower()
        if 'cloudflare' in server:
            result['detected'] = True
            result['provider'] = 'Cloudflare'
        elif 'ecs' in server or 'akamaighost' in server:
            result['detected'] = True
            result['provider'] = 'Akamai'

        via = headers.get('via', '').lower()
        if 'varnish' in via:
            result['detected'] = True
            result['provider'] = result['provider'] or 'Fastly'

        return result

    @staticmethod
    def _build_probe_url(target: str, payload: str) -> str:
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
        return f"{base}?waftest={payload}"

    @staticmethod
    def _match_waf_signature(status: int, headers: dict, body: str):
        """Return WAF name if any signature matches, else None."""
        for sig_status, sig_hdr, sig_hdr_val, sig_body, waf_name in WAF_SIGNATURES:
            # Status code check
            if sig_status is not None and status != sig_status:
                continue

            # Header check
            if sig_hdr is not None:
                hdr_val = headers.get(sig_hdr, '')
                if not hdr_val:
                    continue
                if sig_hdr_val is not None and sig_hdr_val.lower() not in hdr_val.lower():
                    continue

            # Body check
            if sig_body is not None and sig_body.lower() not in body.lower():
                continue

            # If we reach here all non-None conditions matched
            if sig_status is not None or sig_hdr is not None or sig_body is not None:
                return waf_name
        return None

    def _print_summary(self, profile: dict):
        cdn = profile['cdn']
        waf = profile['waf']
        print(f"\n  {Colors.BOLD}Shield Detection Summary:{Colors.RESET}")
        if cdn['detected']:
            print(f"    CDN: {Colors.YELLOW}{cdn['provider']}{Colors.RESET}"
                  f"  edge_ip={cdn.get('edge_ip', '?')}")
        else:
            print(f"    CDN: {Colors.GREEN}None detected{Colors.RESET}")
        if waf['detected']:
            print(f"    WAF: {Colors.YELLOW}{waf['provider']}{Colors.RESET}"
                  f"  block_code={waf.get('block_code', '?')}"
                  f"  confidence={waf['confidence']:.0%}")
        else:
            print(f"    WAF: {Colors.GREEN}None detected{Colors.RESET}")

    def _emit_findings(self, target: str, profile: dict):
        cdn = profile['cdn']
        waf = profile['waf']
        if cdn['detected']:
            self.engine.add_finding(Finding(
                technique='CDN Detected',
                url=target,
                severity='INFO',
                confidence=0.95,
                evidence=f"Provider: {cdn['provider']}, Edge IP: {cdn.get('edge_ip', 'unknown')}",
                remediation='Ensure origin IP is not exposed. Verify CDN config does not leak origin.',
            ))
        if waf['detected']:
            self.engine.add_finding(Finding(
                technique='WAF Detected',
                url=target,
                severity='INFO',
                confidence=waf['confidence'],
                evidence=f"Provider: {waf['provider']}, Block code: {waf.get('block_code')}",
                remediation='WAF is present; payloads may need evasion encoding.',
            ))
