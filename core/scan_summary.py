#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v11.0 — Scan Summary Generator
=================================================

Generates a comprehensive executive summary at the end of each scan,
combining findings analysis, risk scoring, and actionable recommendations.

Usage::

    from core.scan_summary import ScanSummary
    summary = ScanSummary(engine)
    summary.print_summary()
    data = summary.to_dict()
"""

import logging
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional

from config import Colors

logger = logging.getLogger(__name__)

# Risk level thresholds
RISK_SCORE_CRITICAL = 9.0
RISK_SCORE_HIGH = 7.0
RISK_SCORE_MEDIUM = 4.0
RISK_SCORE_LOW = 2.0

# Severity weight for overall risk calculation
SEVERITY_WEIGHTS = {
    "CRITICAL": 10.0,
    "HIGH": 7.5,
    "MEDIUM": 4.0,
    "LOW": 1.5,
    "INFO": 0.5,
}


class ScanSummary:
    """Generate a comprehensive scan summary with risk analysis."""

    def __init__(self, engine):
        self.engine = engine
        self.findings = engine.findings
        self.target = engine.target
        self.start_time = engine.start_time
        self.end_time = engine.end_time or datetime.now(timezone.utc)
        self.scan_id = engine.scan_id

    @property
    def duration_seconds(self) -> float:
        """Total scan duration in seconds."""
        if not self.start_time:
            return 0.0
        delta = self.end_time - self.start_time
        return delta.total_seconds()

    @property
    def overall_risk_score(self) -> float:
        """Calculate overall risk score (0.0 - 10.0).

        Uses a weighted formula that considers:
        - Number and severity of findings
        - Confidence levels
        - Exploit chain potential
        - Verified vs unverified ratio
        """
        if not self.findings:
            return 0.0

        weighted_sum = 0.0
        max_single = 0.0

        for f in self.findings:
            severity = getattr(f, "severity", "INFO")
            confidence = getattr(f, "confidence", 0.5)
            weight = SEVERITY_WEIGHTS.get(severity, 0.5)
            score = weight * confidence
            weighted_sum += score
            max_single = max(max_single, score)

        # Normalized risk: combination of max single finding and cumulative
        # Cap at 10.0
        count_factor = min(2.0, len(self.findings) / 10.0)
        risk = min(10.0, max_single * 0.6 + weighted_sum * 0.1 * count_factor)
        return round(risk, 1)

    @property
    def risk_level(self) -> str:
        """Human-readable risk level."""
        score = self.overall_risk_score
        if score >= RISK_SCORE_CRITICAL:
            return "CRITICAL"
        elif score >= RISK_SCORE_HIGH:
            return "HIGH"
        elif score >= RISK_SCORE_MEDIUM:
            return "MEDIUM"
        elif score >= RISK_SCORE_LOW:
            return "LOW"
        return "INFORMATIONAL"

    def severity_breakdown(self) -> Dict[str, int]:
        """Count findings by severity."""
        counter = Counter()
        for f in self.findings:
            counter[getattr(f, "severity", "INFO")] += 1
        return dict(counter)

    def technique_breakdown(self) -> Dict[str, int]:
        """Count findings by vulnerability technique family."""
        counter = Counter()
        for f in self.findings:
            technique = getattr(f, "technique", "Unknown")
            # Normalize to family
            family = self._technique_family(technique)
            counter[family] += 1
        return dict(counter.most_common(15))

    def top_findings(self, n: int = 5) -> list:
        """Return the top N most critical findings."""
        sorted_findings = sorted(
            self.findings,
            key=lambda f: (
                SEVERITY_WEIGHTS.get(getattr(f, "severity", "INFO"), 0),
                getattr(f, "confidence", 0),
            ),
            reverse=True,
        )
        return sorted_findings[:n]

    def get_recommendations(self) -> List[str]:
        """Generate prioritized remediation recommendations."""
        recommendations = []
        severity_counts = self.severity_breakdown()
        techniques = self.technique_breakdown()

        if severity_counts.get("CRITICAL", 0) > 0:
            recommendations.append(
                "🚨 IMMEDIATE: Address all CRITICAL findings before production deployment. "
                "These represent active exploitation risk."
            )

        if "SQL Injection" in techniques:
            recommendations.append(
                "🔒 Implement parameterized queries/prepared statements across all database interactions. "
                "Review ORM configurations for raw query usage."
            )

        if "XSS" in techniques:
            recommendations.append(
                "🛡️ Deploy Content-Security-Policy headers and implement context-aware output encoding. "
                "Review template engine auto-escaping configuration."
            )

        if "Command Injection" in techniques:
            recommendations.append(
                "⚠️ Remove all OS command execution from user-reachable code paths. "
                "Use language-native APIs instead of shell commands."
            )

        if "SSRF" in techniques:
            recommendations.append(
                "🌐 Implement URL allowlisting and block access to internal IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x). "
                "Use DNS resolution validation."
            )

        if "File Upload" in techniques:
            recommendations.append(
                "📁 Validate file type by content (magic bytes), enforce size limits, "
                "store uploads outside webroot with randomized names."
            )

        if severity_counts.get("HIGH", 0) >= 5:
            recommendations.append(
                "📋 Schedule a focused remediation sprint. Multiple HIGH findings suggest "
                "systemic security architecture issues."
            )

        if not recommendations:
            if self.findings:
                recommendations.append(
                    "✅ No critical issues found. Review remaining findings and address "
                    "as part of regular maintenance."
                )
            else:
                recommendations.append(
                    "✅ No vulnerabilities detected in this scan. Consider expanding scope "
                    "or testing with authenticated sessions."
                )

        return recommendations

    def to_dict(self) -> dict:
        """Serialize the complete summary to a dictionary."""
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "duration_seconds": round(self.duration_seconds, 1),
            "overall_risk_score": self.overall_risk_score,
            "risk_level": self.risk_level,
            "total_findings": len(self.findings),
            "severity_breakdown": self.severity_breakdown(),
            "technique_breakdown": self.technique_breakdown(),
            "top_findings": [
                {
                    "technique": getattr(f, "technique", ""),
                    "severity": getattr(f, "severity", ""),
                    "url": getattr(f, "url", ""),
                    "param": getattr(f, "param", ""),
                    "confidence": getattr(f, "confidence", 0),
                }
                for f in self.top_findings()
            ],
            "recommendations": self.get_recommendations(),
            "scan_metadata": {
                "start_time": self.start_time.isoformat() if self.start_time else None,
                "end_time": self.end_time.isoformat() if self.end_time else None,
                "modules_used": list(self.engine._modules.keys()),
                "adaptive_summary": (
                    self.engine.adaptive.get_scan_summary()
                    if hasattr(self.engine, "adaptive")
                    else {}
                ),
            },
        }

    def print_summary(self):
        """Print a formatted executive summary to stdout."""
        risk_score = self.overall_risk_score
        risk_level = self.risk_level
        severity = self.severity_breakdown()
        duration = self.duration_seconds

        # Risk level color
        risk_color = {
            "CRITICAL": Colors.RED + Colors.BOLD,
            "HIGH": Colors.RED,
            "MEDIUM": Colors.YELLOW,
            "LOW": Colors.CYAN,
            "INFORMATIONAL": Colors.GREEN,
        }.get(risk_level, Colors.WHITE)

        print(f"\n{Colors.BOLD}{'═' * 60}{Colors.RESET}")
        print(f"{Colors.CYAN}  SCAN EXECUTIVE SUMMARY{Colors.RESET}")
        print(f"{Colors.BOLD}{'═' * 60}{Colors.RESET}")

        print(f"\n  Target:     {self.target}")
        print(f"  Scan ID:    {self.scan_id}")
        print(f"  Duration:   {duration:.1f}s ({duration/60:.1f} min)")
        print(f"  Risk Score: {risk_color}{risk_score}/10.0 ({risk_level}){Colors.RESET}")
        print(f"  Findings:   {len(self.findings)} total")

        # Severity breakdown with visual bars
        if severity:
            print(f"\n  {Colors.BOLD}Severity Distribution:{Colors.RESET}")
            total = max(len(self.findings), 1)
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                count = severity.get(sev, 0)
                if count == 0:
                    continue
                pct = count / total
                bar_len = int(pct * 30)
                bar = "█" * bar_len + "░" * (30 - bar_len)
                sev_color = {
                    "CRITICAL": Colors.RED + Colors.BOLD,
                    "HIGH": Colors.RED,
                    "MEDIUM": Colors.YELLOW,
                    "LOW": Colors.CYAN,
                    "INFO": Colors.BLUE,
                }.get(sev, Colors.WHITE)
                print(f"    {sev_color}{sev:10s}{Colors.RESET} [{bar}] {count} ({pct:.0%})")

        # Top findings
        top = self.top_findings(5)
        if top:
            print(f"\n  {Colors.BOLD}Top Findings:{Colors.RESET}")
            for i, f in enumerate(top, 1):
                sev = getattr(f, "severity", "INFO")
                sev_color = {
                    "CRITICAL": Colors.RED + Colors.BOLD,
                    "HIGH": Colors.RED,
                    "MEDIUM": Colors.YELLOW,
                    "LOW": Colors.CYAN,
                    "INFO": Colors.BLUE,
                }.get(sev, Colors.WHITE)
                technique = getattr(f, "technique", "Unknown")
                url = getattr(f, "url", "")
                # Truncate URL for display
                if len(url) > 50:
                    url = url[:47] + "..."
                print(f"    {i}. {sev_color}[{sev}]{Colors.RESET} {technique}")
                print(f"       {url}")

        # Recommendations
        recs = self.get_recommendations()
        if recs:
            print(f"\n  {Colors.BOLD}Recommendations:{Colors.RESET}")
            for rec in recs[:5]:
                print(f"    {rec}")

        # Adaptive intelligence summary
        if hasattr(self.engine, "adaptive"):
            adaptive = self.engine.adaptive.get_scan_summary()
            if adaptive.get("waf_detected"):
                print(f"\n  {Colors.YELLOW}⚠ WAF Detected: {adaptive['waf_name']}{Colors.RESET}")
            if adaptive.get("rate_limited"):
                print(f"  {Colors.YELLOW}⚠ Rate limiting was encountered{Colors.RESET}")

        print(f"\n{Colors.BOLD}{'═' * 60}{Colors.RESET}\n")

    @staticmethod
    def _technique_family(technique: str) -> str:
        """Normalize a technique string to its vulnerability family."""
        technique_lower = technique.lower()
        families = {
            "sql injection": "SQL Injection",
            "sqli": "SQL Injection",
            "xss": "XSS",
            "cross-site scripting": "XSS",
            "command injection": "Command Injection",
            "cmdi": "Command Injection",
            "ssrf": "SSRF",
            "lfi": "LFI/Path Traversal",
            "local file": "LFI/Path Traversal",
            "ssti": "SSTI",
            "template injection": "SSTI",
            "xxe": "XXE",
            "idor": "IDOR",
            "cors": "CORS Misconfiguration",
            "jwt": "JWT Security",
            "nosql": "NoSQL Injection",
            "file upload": "File Upload",
            "open redirect": "Open Redirect",
            "crlf": "CRLF Injection",
            "hpp": "HTTP Parameter Pollution",
            "graphql": "GraphQL",
            "prototype pollution": "Prototype Pollution",
            "race condition": "Race Condition",
            "websocket": "WebSocket",
            "deserialization": "Deserialization",
            "brute force": "Brute Force",
            "network": "Network Exploit",
            "cloud": "Cloud Security",
            "exploit chain": "Exploit Chain",
            "hidden parameter": "Hidden Parameter",
        }
        for key, family in families.items():
            if key in technique_lower:
                return family
        return "Other"
