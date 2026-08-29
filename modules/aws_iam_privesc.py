#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - AWS IAM Privilege Escalation Module
IAM misconfiguration, role assumption, cross-account access.
"""
from config import Colors
from modules.base import BaseModule


class AWSIAMPrivescModule(BaseModule):
    """AWS IAM privilege escalation detection module."""

    name = "AWS IAM Privilege Escalation"
    vuln_type = "aws_iam"

    AWS_ENDPOINTS = [
        "/.aws/credentials", "/.aws/config",
        "/latest/meta-data/iam/security-credentials/",
        "/latest/meta-data/iam/info",
    ]

    def test_url(self, url):
        self._test_aws_credential_exposure(url)
        self._test_aws_metadata_iam(url)

    def test(self, url, method, param, value):
        pass

    def _test_aws_credential_exposure(self, url):
        """Test for exposed AWS credentials."""
        from urllib.parse import urlparse, urljoin
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        for path in self.AWS_ENDPOINTS[:2]:
            try:
                test_url = base + path
                resp = self.requester.request(test_url, "GET", timeout=5)
                if resp and resp.status_code == 200 and ("aws_access_key" in resp.text or "role_arn" in resp.text):
                    self.engine.add_finding(self._finding(
                        technique="AWS Credential Exposure",
                        url=test_url,
                        severity="CRITICAL",
                        confidence=0.9,
                        param=path,
                        payload=test_url,
                        evidence=f"AWS credentials found at {path}",
                    ))
            except Exception:
                pass

    def _test_aws_metadata_iam(self, url):
        """Test for AWS metadata IAM endpoint."""
        try:
            resp = self.requester.request(
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "GET", timeout=3
            )
            if resp and resp.status_code == 200 and resp.text.strip():
                self.engine.add_finding(self._finding(
                    technique="AWS IAM Role Metadata Accessible",
                    url=url,
                    severity="CRITICAL",
                    confidence=0.95,
                    param="metadata",
                    payload="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                    evidence=f"IAM role: {resp.text.strip()[:200]}",
                ))
        except Exception:
            pass

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
