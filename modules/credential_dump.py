#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Credential Dumping Module
Network-based credential extraction: exposed .git, .env, config files, backup databases.
"""
import re
from config import Colors
from modules.base import BaseModule


class CredentialDumpModule(BaseModule):
    """Network-based credential dumping module."""

    name = "Credential Dumping"
    vuln_type = "credential_dump"
    requires_reflection = False

    CREDENTIAL_PATHS = [
        "/.env", "/.env.bak", "/.env.local", "/.env.production",
        "/config.php", "/config.php.bak", "/wp-config.php",
        "/config.yml", "/config.yaml", "/config.json",
        "/database.yml", "/settings.py", "/local_settings.py",
        "/application.properties", "/appsettings.json",
        "/.git/config", "/.git/HEAD", "/.svn/wc.db",
        "/.aws/credentials", "/.aws/config", "/.kube/config",
        "/credentials.json", "/service-account.json",
        "/id_rsa", "/id_dsa", "/.ssh/id_rsa",
        "/server.key", "/server.pem", "/private.key",
        "/dump.sql", "/backup.sql", "/db.sql",
    ]

    CREDENTIAL_PATTERNS = [
        (r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{3,})["\']', "Password"),
        (r'(?i)(?:secret|secret_key|SECRET_KEY)\s*[=:]\s*["\']([^"\']{8,})["\']', "Secret Key"),
        (r'(?i)(?:api_key|apikey|API_KEY)\s*[=:]\s*["\']([^"\']{8,})["\']', "API Key"),
        (r'(?i)(?:token|auth_token|access_token)\s*[=:]\s*["\']([^"\']{8,})["\']', "Token"),
        (r'(?i)(?:AWS_ACCESS_KEY_ID|aws_access_key_id)\s*[=:]\s*["\']?([A-Z0-9]{20})["\']?', "AWS Key"),
        (r'(?i)(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', "AWS Secret"),
        (r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}', "AWS Key ID"),
        (r'ghp_[A-Za-z0-9]{36}', "GitHub PAT"),
        (r'github_pat_[A-Za-z0-9_]{82}', "GitHub Fine-Grained PAT"),
        (r'(?:mysql|postgres|mongodb|redis)://[^\s"\'<>]{10,}', "Database URL"),
        (r'-----BEGIN (?:RSA |OPENSSH |DSA |EC )?PRIVATE KEY-----', "Private Key"),
    ]

    def test_url(self, url):
        self._test_credential_exposure(url)

    def test(self, url, method, param, value):
        pass

    def _test_credential_exposure(self, url):
        """Test for exposed credential files."""
        from urllib.parse import urlparse, urljoin
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        for path in self.CREDENTIAL_PATHS:
            try:
                test_url = base + path
                resp = self.requester.request(test_url, "GET", timeout=5)
                if resp and resp.status_code == 200 and len(resp.text) > 5:
                    # Check for credential patterns
                    for pattern, cred_type in self.CREDENTIAL_PATTERNS:
                        matches = re.findall(pattern, resp.text)
                        if matches:
                            self.engine.add_finding(self._finding(
                                technique=f"Credential Exposure ({cred_type})",
                                url=test_url,
                                severity="CRITICAL",
                                confidence=0.85,
                                param=path,
                                payload=test_url,
                                evidence=f"{cred_type} found in {path}: {matches[0][:50]}...",
                            ))
                            break
                    else:
                        # File exists but no credentials found
                        if any(ext in path for ext in [".env", ".key", ".pem", "credentials", "password"]):
                            self.engine.add_finding(self._finding(
                                technique=f"Sensitive File Exposure ({path})",
                                url=test_url,
                                severity="MEDIUM",
                                confidence=0.7,
                                param=path,
                                payload=test_url,
                                evidence=f"Sensitive file accessible: {path} ({len(resp.text)} bytes)",
                            ))
            except Exception:
                pass

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
