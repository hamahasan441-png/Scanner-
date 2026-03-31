#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - VulnX CMS Module
CMS vulnerability detection powered by vulnx
(https://github.com/anouarbensaad/vulnx)
"""

import os
import re
import sys
import shutil
import subprocess
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Colors, Config


# Path where vulnx is expected to be installed
VULNX_DIR = os.path.join(Config.BASE_DIR, 'tools', 'vulnx')
VULNX_REPO = 'https://github.com/anouarbensaad/vulnx.git'


class VulnXModule:
    """CMS Vulnerability Scanner module powered by vulnx."""

    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.name = "VulnX CMS Scanner"
        self._vulnx_available = self._check_vulnx()

    # ------------------------------------------------------------------
    # Installation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _check_vulnx() -> bool:
        """Return True if vulnx is installed locally."""
        return os.path.isfile(os.path.join(VULNX_DIR, 'vulnx.py'))

    @staticmethod
    def install_vulnx() -> bool:
        """Clone vulnx into the tools directory."""
        try:
            os.makedirs(os.path.dirname(VULNX_DIR), exist_ok=True)
            if os.path.isdir(VULNX_DIR):
                shutil.rmtree(VULNX_DIR)
            subprocess.run(
                ['git', 'clone', '--depth', '1', VULNX_REPO, VULNX_DIR],
                check=True,
                capture_output=True,
                timeout=120,
            )
            print(f"{Colors.success('vulnx installed successfully')}")
            return True
        except Exception as exc:
            print(f"{Colors.error(f'Failed to install vulnx: {exc}')}")
            return False

    # ------------------------------------------------------------------
    # Module interface (required by engine)
    # ------------------------------------------------------------------

    def test(self, url: str, method: str, param: str, value: str):
        """Parameter-level test — not applicable for CMS detection."""
        pass

    def test_url(self, url: str):
        """Run CMS detection and vulnerability checks on *url*."""
        # Step 1 — lightweight CMS fingerprinting via HTTP response
        cms = self._detect_cms(url)

        if not cms:
            if self.engine.config.get('verbose'):
                print(f"{Colors.info(f'No CMS detected on {url}')}")
            return

        print(f"{Colors.info(f'CMS detected: {cms} on {url}')}")

        # Step 2 — run vulnx if available
        if self._vulnx_available:
            self._run_vulnx(url, cms)
        else:
            # Fallback: built-in lightweight CMS checks
            self._builtin_cms_check(url, cms)

    # ------------------------------------------------------------------
    # CMS fingerprinting (built-in, no external tool needed)
    # ------------------------------------------------------------------

    # CMS signatures: pattern → CMS name
    _CMS_SIGNATURES = {
        'wordpress': [
            re.compile(r'/wp-content/', re.I),
            re.compile(r'/wp-includes/', re.I),
            re.compile(r'<meta\s+name=["\']generator["\'][^>]*WordPress', re.I),
        ],
        'joomla': [
            re.compile(r'/media/jui/', re.I),
            re.compile(r'<meta\s+name=["\']generator["\'][^>]*Joomla', re.I),
            re.compile(r'/components/com_', re.I),
        ],
        'drupal': [
            re.compile(r'Drupal\.settings', re.I),
            re.compile(r'<meta\s+name=["\']generator["\'][^>]*Drupal', re.I),
            re.compile(r'/sites/default/files/', re.I),
        ],
        'prestashop': [
            re.compile(r'/modules/prestashop', re.I),
            re.compile(r'<meta\s+name=["\']generator["\'][^>]*PrestaShop', re.I),
            re.compile(r'prestashop', re.I),
        ],
        'magento': [
            re.compile(r'/skin/frontend/', re.I),
            re.compile(r'Mage\.Cookies', re.I),
            re.compile(r'/mage/', re.I),
        ],
        'opencart': [
            re.compile(r'catalog/view/theme', re.I),
            re.compile(r'route=common/', re.I),
        ],
    }

    # Known CMS-specific paths that may reveal sensitive info
    _CMS_PATHS = {
        'wordpress': [
            '/wp-login.php', '/wp-admin/', '/wp-json/', '/xmlrpc.php',
            '/wp-config.php.bak', '/wp-content/debug.log',
            '/readme.html', '/license.txt',
        ],
        'joomla': [
            '/administrator/', '/configuration.php-dist',
            '/README.txt', '/web.config.txt',
        ],
        'drupal': [
            '/CHANGELOG.txt', '/user/login', '/admin/',
            '/core/install.php', '/update.php',
        ],
        'prestashop': [
            '/admin/', '/install/', '/docs/readme_en.txt',
        ],
        'magento': [
            '/admin/', '/downloader/', '/app/etc/local.xml',
            '/RELEASE_NOTES.txt',
        ],
        'opencart': [
            '/admin/', '/install/', '/system/logs/error.log',
        ],
    }

    def _detect_cms(self, url: str) -> str:
        """Detect the CMS used by *url* via response analysis."""
        try:
            response = self.requester.request(url, 'GET')
            if not response:
                return ''

            body = response.text[:10000]
            headers_str = str(response.headers)

            for cms, patterns in self._CMS_SIGNATURES.items():
                for pat in patterns:
                    if pat.search(body) or pat.search(headers_str):
                        return cms
        except Exception:
            pass
        return ''

    # ------------------------------------------------------------------
    # Built-in lightweight CMS checks (no vulnx dependency)
    # ------------------------------------------------------------------

    def _builtin_cms_check(self, url: str, cms: str):
        """Probe known CMS paths to find exposed endpoints."""
        from core.engine import Finding

        base = urlparse(url)
        base_url = f"{base.scheme}://{base.netloc}"

        paths = self._CMS_PATHS.get(cms, [])
        for path in paths:
            full_url = base_url + path
            try:
                resp = self.requester.request(full_url, 'GET')
                if resp and resp.status_code == 200:
                    snippet = resp.text[:120].strip()
                    finding = Finding(
                        technique=f"CMS Exposure ({cms})",
                        url=full_url,
                        severity='MEDIUM',
                        confidence=0.7,
                        param='',
                        payload=path,
                        evidence=f"CMS: {cms} — accessible path: {path} "
                                 f"(status {resp.status_code}). "
                                 f"Snippet: {snippet}",
                    )
                    self.engine.add_finding(finding)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Run external vulnx tool
    # ------------------------------------------------------------------

    def _run_vulnx(self, url: str, cms: str):
        """Execute vulnx against *url* and parse its output."""
        from core.engine import Finding

        vulnx_script = os.path.join(VULNX_DIR, 'vulnx.py')
        cmd = [sys.executable, vulnx_script, '-u', url, '--cms', '--dns', '--sub']

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                cwd=VULNX_DIR,
            )
            output = result.stdout + result.stderr

            if self.engine.config.get('verbose'):
                print(f"{Colors.info(f'vulnx output:\n{output[:500]}')}")

            # Parse vulnx output for vulnerability indicators
            vuln_patterns = [
                (r'\[VULNERABLE\]\s*(.*)', 'HIGH'),
                (r'\[EXPLOIT\]\s*(.*)', 'CRITICAL'),
                (r'\[INFO\]\s*(.*)', 'INFO'),
            ]

            for pattern, severity in vuln_patterns:
                for match in re.finditer(pattern, output, re.IGNORECASE):
                    detail = match.group(1).strip()
                    finding = Finding(
                        technique=f"VulnX CMS Vulnerability ({cms})",
                        url=url,
                        severity=severity,
                        confidence=0.8 if severity != 'INFO' else 0.5,
                        param='',
                        payload='vulnx scan',
                        evidence=detail[:300],
                    )
                    self.engine.add_finding(finding)

            # If vulnx produced no parsed findings, still record CMS info
            if not any(re.search(p, output, re.I) for p, _ in vuln_patterns):
                finding = Finding(
                    technique=f"CMS Detection ({cms})",
                    url=url,
                    severity='INFO',
                    confidence=0.8,
                    param='',
                    payload='vulnx detection',
                    evidence=f"Detected CMS: {cms}. vulnx scan completed.",
                )
                self.engine.add_finding(finding)

        except subprocess.TimeoutExpired:
            print(f"{Colors.warning(f'vulnx timed out on {url}')}")
        except Exception as exc:
            if self.engine.config.get('verbose'):
                print(f"{Colors.error(f'vulnx error: {exc}')}")
            # Fall back to built-in checks
            self._builtin_cms_check(url, cms)
