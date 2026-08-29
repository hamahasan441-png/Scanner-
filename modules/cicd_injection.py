#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - CI/CD Injection Module
Pipeline injection, Jenkins, GitLab CI, GitHub Actions, Azure DevOps.
"""
from config import Colors
from modules.base import BaseModule


class CICDInjectionModule(BaseModule):
    """CI/CD pipeline injection detection module."""

    name = "CI/CD Injection"
    vuln_type = "cicd"

    CICD_PATHS = [
        "/jenkins", "/jenkins/", "/jenkins/login", "/jenkins/script",
        "/gitlab-ci.yml", "/.gitlab-ci.yml", "/.github/workflows/",
        "/bitbucket-pipelines.yml", "/azure-pipelines.yml",
        "/Jenkinsfile", "/.circleci/config.yml", "/.travis.yml",
        "/drone.yml", "/.drone.yml", "/buildkite.yml",
        "/pipeline", "/api/pipelines", "/ci", "/cd",
    ]

    def test_url(self, url):
        self._test_cicd_exposure(url)
        self._test_jenkins_script(url)

    def test(self, url, method, param, value):
        pass

    def _test_cicd_exposure(self, url):
        """Test for exposed CI/CD configuration files."""
        from urllib.parse import urlparse, urljoin
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        for path in self.CICD_PATHS:
            try:
                test_url = base + path
                resp = self.requester.request(test_url, "GET", timeout=5)
                if resp and resp.status_code == 200:
                    text = resp.text.lower()
                    if any(kw in text for kw in ["pipeline", "stage", "job", "jenkins", "workflow", "script"]):
                        self.engine.add_finding(self._finding(
                            technique="CI/CD Configuration Exposure",
                            url=test_url,
                            severity="MEDIUM",
                            confidence=0.7,
                            param=path,
                            payload=test_url,
                            evidence=f"CI/CD config found at {path}",
                        ))
            except Exception:
                pass

    def _test_jenkins_script(self, url):
        """Test for Jenkins Script Console exposure."""
        from urllib.parse import urlparse, urljoin
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        jenkins_paths = ["/jenkins/script", "/jenkins/manage", "/jenkins/systemInfo",
                         "/jenkins/env-vars", "/jenkins/asynchPeople"]
        for path in jenkins_paths:
            try:
                test_url = base + path
                resp = self.requester.request(test_url, "GET", timeout=5)
                if resp and resp.status_code == 200 and "script" in resp.text.lower():
                    self.engine.add_finding(self._finding(
                        technique="Jenkins Script Console",
                        url=test_url,
                        severity="CRITICAL",
                        confidence=0.6,
                        param=path,
                        payload=test_url,
                        evidence=f"Jenkins Script Console accessible at {path}",
                    ))
                    break
            except Exception:
                pass

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
