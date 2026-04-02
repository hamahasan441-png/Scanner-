#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - OSINT Reconnaissance Module
Google dorking, GitHub secret leak detection, Wayback Machine harvesting
"""

import re
from urllib.parse import urlparse, urljoin

from config import Colors


class OSINTModule:
    """OSINT Reconnaissance Module"""
    
    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.name = "OSINT Recon"
    
    def test(self, url, method, param, value):
        """Not used for OSINT — recon is URL-based"""
        pass
    
    def test_url(self, url):
        """Run OSINT reconnaissance on target URL"""
        domain = urlparse(url).hostname or urlparse(url).netloc
        self._generate_google_dorks(domain)
        self._check_github_leaks(domain)
        self._wayback_harvest(url)
        self._check_robots_sitemap(url)
    
    def _generate_google_dorks(self, domain):
        """Generate Google dorking payloads"""
        dorks = [
            f'site:{domain} filetype:sql',
            f'site:{domain} filetype:env',
            f'site:{domain} filetype:log',
            f'site:{domain} filetype:conf',
            f'site:{domain} filetype:bak',
            f'site:{domain} inurl:admin',
            f'site:{domain} inurl:login',
            f'site:{domain} inurl:api',
            f'site:{domain} intitle:"index of"',
            f'site:{domain} inurl:wp-config',
            f'site:{domain} ext:php intitle:phpinfo',
            f'site:{domain} inurl:".git"',
            f'site:{domain} inurl:swagger',
            f'site:{domain} filetype:xml sitemap',
        ]
        from core.engine import Finding
        finding = Finding(
            technique="OSINT (Google Dorks Generated)",
            url=f"https://www.google.com/search?q=site:{domain}",
            severity='INFO', confidence=1.0,
            param='N/A', payload=f'{len(dorks)} dorks generated',
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
        ]
        from core.engine import Finding
        finding = Finding(
            technique="OSINT (GitHub Leak Queries Generated)",
            url=f"https://github.com/search?q={domain}&type=code",
            severity='INFO', confidence=1.0,
            param='N/A', payload=f'{len(search_queries)} queries generated',
            evidence="; ".join(search_queries[:3]) + f"... ({len(search_queries)} total)",
        )
        self.engine.add_finding(finding)
    
    def _wayback_harvest(self, url):
        """Harvest URLs from Wayback Machine"""
        domain = urlparse(url).hostname
        wayback_url = f'https://web.archive.org/cdx/search/cdx?url={domain}/*&output=text&fl=original&collapse=urlkey&limit=100'
        try:
            response = self.requester.request(wayback_url, 'GET')
            if response and response.status_code == 200:
                urls = [line.strip() for line in response.text.strip().split('\n') if line.strip()]
                if urls:
                    interesting = [u for u in urls if any(ext in u.lower() for ext in ['.php', '.asp', '.jsp', '.env', '.bak', '.sql', '.conf', 'api/', 'admin/'])]
                    from core.engine import Finding
                    finding = Finding(
                        technique="OSINT (Wayback Machine)",
                        url=wayback_url, severity='INFO', confidence=0.9,
                        param='N/A', payload=f'{len(urls)} URLs found',
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
            response = self.requester.request(robots_url, 'GET')
            if response and response.status_code == 200 and 'disallow' in response.text.lower():
                disallowed = re.findall(r'Disallow:\s*(.+)', response.text, re.IGNORECASE)
                if disallowed:
                    findings_data.append(f"robots.txt: {len(disallowed)} disallowed paths")
        except Exception:
            pass
        
        # Check sitemap
        try:
            sitemap_url = f"{base_url}/sitemap.xml"
            response = self.requester.request(sitemap_url, 'GET')
            if response and response.status_code == 200 and '<loc>' in response.text.lower():
                locs = re.findall(r'<loc>(.*?)</loc>', response.text, re.IGNORECASE)
                if locs:
                    findings_data.append(f"sitemap.xml: {len(locs)} URLs")
        except Exception:
            pass
        
        if findings_data:
            from core.engine import Finding
            finding = Finding(
                technique="OSINT (Robots/Sitemap Analysis)",
                url=base_url, severity='INFO', confidence=0.9,
                param='N/A', payload='robots.txt + sitemap.xml',
                evidence="; ".join(findings_data),
            )
            self.engine.add_finding(finding)
