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
