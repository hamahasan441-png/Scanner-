#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Compliance Mapping Engine
Maps vulnerability findings to industry compliance frameworks:
  - OWASP Top 10 (2021)
  - PCI DSS v4.0
  - CIS Controls v8
  - NIST SP 800-53
  - SANS Top 25

Provides gap analysis, compliance scoring, and audit-ready reports.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# OWASP Top 10 (2021) mapping
# ---------------------------------------------------------------------------
OWASP_TOP_10 = {
    "A01": {
        "id": "A01:2021",
        "name": "Broken Access Control",
        "cwe_ids": ["CWE-200", "CWE-201", "CWE-352", "CWE-566", "CWE-639", "CWE-862", "CWE-863", "CWE-913"],
        "keywords": [
            "idor",
            "access control",
            "privilege",
            "authorization",
            "cors",
            "csrf",
            "directory traversal",
            "path traversal",
        ],
    },
    "A02": {
        "id": "A02:2021",
        "name": "Cryptographic Failures",
        "cwe_ids": [
            "CWE-261",
            "CWE-296",
            "CWE-310",
            "CWE-319",
            "CWE-321",
            "CWE-322",
            "CWE-323",
            "CWE-324",
            "CWE-325",
            "CWE-326",
            "CWE-327",
            "CWE-328",
            "CWE-329",
            "CWE-330",
            "CWE-331",
        ],
        "keywords": ["crypto", "ssl", "tls", "certificate", "weak cipher", "plaintext", "encryption", "jwt"],
    },
    "A03": {
        "id": "A03:2021",
        "name": "Injection",
        "cwe_ids": [
            "CWE-20",
            "CWE-74",
            "CWE-75",
            "CWE-77",
            "CWE-78",
            "CWE-79",
            "CWE-80",
            "CWE-83",
            "CWE-87",
            "CWE-88",
            "CWE-89",
            "CWE-90",
            "CWE-91",
            "CWE-93",
            "CWE-94",
            "CWE-95",
            "CWE-96",
            "CWE-97",
            "CWE-98",
            "CWE-99",
            "CWE-113",
            "CWE-116",
            "CWE-138",
            "CWE-184",
        ],
        "keywords": [
            "sql injection",
            "sqli",
            "xss",
            "cross-site scripting",
            "command injection",
            "cmdi",
            "ldap injection",
            "nosql",
            "ssti",
            "xxe",
            "crlf",
            "header injection",
            "template injection",
        ],
    },
    "A04": {
        "id": "A04:2021",
        "name": "Insecure Design",
        "cwe_ids": [
            "CWE-73",
            "CWE-183",
            "CWE-209",
            "CWE-213",
            "CWE-235",
            "CWE-256",
            "CWE-257",
            "CWE-266",
            "CWE-269",
            "CWE-280",
            "CWE-311",
            "CWE-312",
            "CWE-313",
            "CWE-316",
            "CWE-419",
            "CWE-430",
            "CWE-434",
            "CWE-444",
            "CWE-451",
            "CWE-472",
        ],
        "keywords": ["design flaw", "business logic", "race condition", "file upload", "insecure design"],
    },
    "A05": {
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "cwe_ids": [
            "CWE-2",
            "CWE-11",
            "CWE-13",
            "CWE-15",
            "CWE-16",
            "CWE-260",
            "CWE-315",
            "CWE-520",
            "CWE-526",
            "CWE-537",
            "CWE-541",
            "CWE-547",
        ],
        "keywords": [
            "misconfiguration",
            "default",
            "missing header",
            "security header",
            "directory listing",
            "verbose error",
            "information disclosure",
            "cors misconfiguration",
        ],
    },
    "A06": {
        "id": "A06:2021",
        "name": "Vulnerable and Outdated Components",
        "cwe_ids": ["CWE-1104"],
        "keywords": [
            "outdated",
            "vulnerable component",
            "cve",
            "tech exploit",
            "network exploit",
            "version",
            "unpatched",
        ],
    },
    "A07": {
        "id": "A07:2021",
        "name": "Identification and Authentication Failures",
        "cwe_ids": [
            "CWE-255",
            "CWE-259",
            "CWE-287",
            "CWE-288",
            "CWE-290",
            "CWE-294",
            "CWE-295",
            "CWE-297",
            "CWE-300",
            "CWE-302",
            "CWE-304",
            "CWE-306",
            "CWE-307",
            "CWE-346",
            "CWE-384",
            "CWE-521",
            "CWE-613",
            "CWE-620",
            "CWE-640",
            "CWE-798",
            "CWE-940",
            "CWE-1216",
        ],
        "keywords": ["authentication", "brute force", "credential", "session", "password", "login"],
    },
    "A08": {
        "id": "A08:2021",
        "name": "Software and Data Integrity Failures",
        "cwe_ids": [
            "CWE-345",
            "CWE-353",
            "CWE-426",
            "CWE-494",
            "CWE-502",
            "CWE-565",
            "CWE-784",
            "CWE-829",
            "CWE-830",
            "CWE-915",
        ],
        "keywords": ["deserialization", "prototype pollution", "integrity", "supply chain", "unsigned"],
    },
    "A09": {
        "id": "A09:2021",
        "name": "Security Logging and Monitoring Failures",
        "cwe_ids": ["CWE-117", "CWE-223", "CWE-532", "CWE-778"],
        "keywords": ["logging", "monitoring", "audit", "log injection"],
    },
    "A10": {
        "id": "A10:2021",
        "name": "Server-Side Request Forgery (SSRF)",
        "cwe_ids": ["CWE-918"],
        "keywords": ["ssrf", "server-side request forgery"],
    },
}


# ---------------------------------------------------------------------------
# PCI DSS v4.0 mapping
# ---------------------------------------------------------------------------
PCI_DSS = {
    "R1": {
        "id": "1",
        "name": "Install and Maintain Network Security Controls",
        "keywords": ["firewall", "network", "port scan", "segmentation"],
    },
    "R2": {
        "id": "2",
        "name": "Apply Secure Configurations",
        "keywords": ["default", "misconfiguration", "hardening", "security header"],
    },
    "R3": {
        "id": "3",
        "name": "Protect Stored Account Data",
        "keywords": ["data exposure", "database", "dump", "encryption", "storage"],
    },
    "R4": {
        "id": "4",
        "name": "Protect Cardholder Data with Strong Cryptography",
        "keywords": ["ssl", "tls", "crypto", "certificate", "plaintext"],
    },
    "R5": {
        "id": "5",
        "name": "Protect Against Malicious Software",
        "keywords": ["malware", "shell", "upload", "webshell"],
    },
    "R6": {
        "id": "6",
        "name": "Develop and Maintain Secure Systems and Software",
        "keywords": ["sqli", "xss", "injection", "vulnerability", "cve", "patch"],
    },
    "R7": {
        "id": "7",
        "name": "Restrict Access to System Components",
        "keywords": ["access control", "authorization", "idor", "privilege"],
    },
    "R8": {
        "id": "8",
        "name": "Identify Users and Authenticate Access",
        "keywords": ["authentication", "brute force", "password", "mfa", "jwt"],
    },
    "R10": {"id": "10", "name": "Log and Monitor All Access", "keywords": ["logging", "monitoring", "audit trail"]},
    "R11": {
        "id": "11",
        "name": "Test Security of Systems and Networks Regularly",
        "keywords": ["scan", "penetration test", "assessment"],
    },
    "R12": {
        "id": "12",
        "name": "Support Information Security with Policies",
        "keywords": ["policy", "governance", "compliance"],
    },
}


# ---------------------------------------------------------------------------
# NIST SP 800-53 Rev 5 mapping (selected controls)
# ---------------------------------------------------------------------------
NIST_800_53 = {
    "AC": {
        "id": "AC",
        "name": "Access Control",
        "keywords": ["access control", "authorization", "idor", "cors", "privilege"],
    },
    "AU": {"id": "AU", "name": "Audit and Accountability", "keywords": ["audit", "logging", "monitoring"]},
    "CA": {
        "id": "CA",
        "name": "Assessment, Authorization, and Monitoring",
        "keywords": ["scan", "assessment", "monitoring", "vulnerability"],
    },
    "CM": {
        "id": "CM",
        "name": "Configuration Management",
        "keywords": ["misconfiguration", "default", "hardening", "security header"],
    },
    "IA": {
        "id": "IA",
        "name": "Identification and Authentication",
        "keywords": ["authentication", "brute force", "password", "jwt", "session"],
    },
    "RA": {"id": "RA", "name": "Risk Assessment", "keywords": ["vulnerability", "cve", "risk", "severity", "cvss"]},
    "SC": {
        "id": "SC",
        "name": "System and Communications Protection",
        "keywords": ["encryption", "ssl", "tls", "ssrf", "injection", "xss"],
    },
    "SI": {
        "id": "SI",
        "name": "System and Information Integrity",
        "keywords": ["injection", "sqli", "xss", "malware", "integrity", "patch"],
    },
}


# ---------------------------------------------------------------------------
# CIS Controls v8 mapping
# ---------------------------------------------------------------------------
CIS_CONTROLS = {
    "CIS-1": {
        "id": "1",
        "name": "Inventory and Control of Enterprise Assets",
        "keywords": ["discovery", "asset", "subdomain", "port scan"],
    },
    "CIS-2": {
        "id": "2",
        "name": "Inventory and Control of Software Assets",
        "keywords": ["tech detect", "software", "version", "component"],
    },
    "CIS-3": {"id": "3", "name": "Data Protection", "keywords": ["data exposure", "encryption", "dump", "plaintext"]},
    "CIS-4": {
        "id": "4",
        "name": "Secure Configuration",
        "keywords": ["misconfiguration", "default", "hardening", "security header"],
    },
    "CIS-5": {
        "id": "5",
        "name": "Account Management",
        "keywords": ["authentication", "password", "brute force", "credential"],
    },
    "CIS-7": {
        "id": "7",
        "name": "Continuous Vulnerability Management",
        "keywords": ["vulnerability", "cve", "scan", "patch", "exploit"],
    },
    "CIS-8": {"id": "8", "name": "Audit Log Management", "keywords": ["audit", "logging", "monitoring"]},
    "CIS-9": {
        "id": "9",
        "name": "Email and Web Browser Protections",
        "keywords": ["xss", "phishing", "open redirect", "csp"],
    },
    "CIS-10": {"id": "10", "name": "Malware Defenses", "keywords": ["malware", "shell", "upload", "webshell"]},
    "CIS-16": {
        "id": "16",
        "name": "Application Software Security",
        "keywords": ["sqli", "xss", "injection", "ssti", "deserialization"],
    },
}


# ---------------------------------------------------------------------------
# SANS Top 25 (CWE-based)
# ---------------------------------------------------------------------------
SANS_TOP_25_CWES = {
    "CWE-787",
    "CWE-79",
    "CWE-89",
    "CWE-416",
    "CWE-78",
    "CWE-20",
    "CWE-125",
    "CWE-22",
    "CWE-352",
    "CWE-434",
    "CWE-862",
    "CWE-476",
    "CWE-287",
    "CWE-190",
    "CWE-502",
    "CWE-77",
    "CWE-119",
    "CWE-798",
    "CWE-918",
    "CWE-306",
    "CWE-362",
    "CWE-269",
    "CWE-94",
    "CWE-863",
    "CWE-276",
}


# ---------------------------------------------------------------------------
# Compliance Result dataclasses
# ---------------------------------------------------------------------------
@dataclass
class ComplianceMapping:
    """Single finding-to-compliance mapping."""

    finding_technique: str
    finding_severity: str
    framework: str  # owasp | pci_dss | nist | cis | sans
    control_id: str
    control_name: str
    match_reason: str  # keyword or CWE match
    cwe_id: str = ""

    def to_dict(self) -> dict:
        return {
            "finding_technique": self.finding_technique,
            "finding_severity": self.finding_severity,
            "framework": self.framework,
            "control_id": self.control_id,
            "control_name": self.control_name,
            "match_reason": self.match_reason,
            "cwe_id": self.cwe_id,
        }


@dataclass
class ComplianceReport:
    """Full compliance analysis result."""

    scan_id: str = ""
    target: str = ""
    timestamp: str = ""
    total_findings: int = 0
    mappings: List[ComplianceMapping] = field(default_factory=list)
    framework_scores: Dict[str, dict] = field(default_factory=dict)
    gaps: List[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "timestamp": self.timestamp,
            "total_findings": self.total_findings,
            "mappings": [m.to_dict() for m in self.mappings],
            "framework_scores": self.framework_scores,
            "gaps": self.gaps,
        }


# ---------------------------------------------------------------------------
# Compliance Engine
# ---------------------------------------------------------------------------
class ComplianceEngine:
    """Map findings to compliance frameworks and compute coverage scores."""

    FRAMEWORKS = {
        "owasp": OWASP_TOP_10,
        "pci_dss": PCI_DSS,
        "nist": NIST_800_53,
        "cis": CIS_CONTROLS,
    }

    def analyze(
        self, findings: list, scan_id: str = "", target: str = "", frameworks: Optional[List[str]] = None
    ) -> ComplianceReport:
        """Run compliance analysis on a list of Finding objects.

        Args:
            findings: List of Finding dataclass instances (from engine).
            scan_id: Scan identifier.
            target: Target URL.
            frameworks: List of frameworks to check (default: all).

        Returns:
            ComplianceReport with mappings, scores, and gaps.
        """
        if frameworks is None:
            frameworks = list(self.FRAMEWORKS.keys())

        report = ComplianceReport(
            scan_id=scan_id,
            target=target,
            timestamp=datetime.now(timezone.utc).isoformat(),
            total_findings=len(findings),
        )

        for fw_name in frameworks:
            fw_controls = self.FRAMEWORKS.get(fw_name)
            if not fw_controls:
                continue
            report.mappings.extend(self._map_framework(findings, fw_name, fw_controls))
            report.framework_scores[fw_name] = self._score_framework(
                findings,
                fw_name,
                fw_controls,
                report.mappings,
            )

        # SANS Top 25 (CWE-based)
        if "sans" in frameworks or frameworks == list(self.FRAMEWORKS.keys()):
            report.mappings.extend(self._map_sans(findings))

        # Gap analysis
        report.gaps = self._gap_analysis(report.mappings, frameworks)

        return report

    def _map_framework(self, findings: list, fw_name: str, controls: dict) -> List[ComplianceMapping]:
        """Map findings to a specific framework's controls."""
        mappings = []
        for finding in findings:
            technique_lower = getattr(finding, "technique", "").lower()
            cwe = getattr(finding, "cwe_id", "")
            severity = getattr(finding, "severity", "INFO")

            for ctrl_key, ctrl in controls.items():
                matched = False
                reason = ""

                # CWE match (for OWASP which has CWE lists)
                if "cwe_ids" in ctrl and cwe:
                    if cwe in ctrl["cwe_ids"]:
                        matched = True
                        reason = f"CWE match: {cwe}"

                # Keyword match
                if not matched and "keywords" in ctrl:
                    for kw in ctrl["keywords"]:
                        if kw in technique_lower:
                            matched = True
                            reason = f"keyword match: {kw}"
                            break

                if matched:
                    mappings.append(
                        ComplianceMapping(
                            finding_technique=getattr(finding, "technique", ""),
                            finding_severity=severity,
                            framework=fw_name,
                            control_id=ctrl.get("id", ctrl_key),
                            control_name=ctrl["name"],
                            match_reason=reason,
                            cwe_id=cwe,
                        )
                    )
        return mappings

    def _map_sans(self, findings: list) -> List[ComplianceMapping]:
        """Map findings to SANS Top 25 by CWE."""
        mappings = []
        for finding in findings:
            cwe = getattr(finding, "cwe_id", "")
            if cwe in SANS_TOP_25_CWES:
                mappings.append(
                    ComplianceMapping(
                        finding_technique=getattr(finding, "technique", ""),
                        finding_severity=getattr(finding, "severity", "INFO"),
                        framework="sans",
                        control_id=cwe,
                        control_name=f"SANS Top 25 — {cwe}",
                        match_reason=f"CWE match: {cwe}",
                        cwe_id=cwe,
                    )
                )
        return mappings

    def _score_framework(
        self, findings: list, fw_name: str, controls: dict, all_mappings: List[ComplianceMapping]
    ) -> dict:
        """Compute a compliance score for a framework.

        Score = percentage of controls that have NO findings mapped to them.
        A higher score means better compliance (fewer issues found).
        """
        fw_mappings = [m for m in all_mappings if m.framework == fw_name]
        triggered_controls = {m.control_id for m in fw_mappings}
        total_controls = len(controls)
        failing = len(triggered_controls)
        passing = total_controls - failing

        severity_weight = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2, "INFO": 1}
        risk_score = sum(severity_weight.get(m.finding_severity, 1) for m in fw_mappings)

        score_pct = (passing / total_controls * 100) if total_controls > 0 else 100.0

        return {
            "total_controls": total_controls,
            "passing": passing,
            "failing": failing,
            "score_pct": round(score_pct, 1),
            "risk_score": risk_score,
            "triggered_controls": sorted(triggered_controls),
        }

    def _gap_analysis(self, mappings: List[ComplianceMapping], frameworks: List[str]) -> List[dict]:
        """Identify the most critical compliance gaps."""
        gaps = []
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

        # Group by framework + control
        control_map: Dict[str, List[ComplianceMapping]] = {}
        for m in mappings:
            key = f"{m.framework}:{m.control_id}"
            control_map.setdefault(key, []).append(m)

        for key, ctrl_mappings in control_map.items():
            worst = min(ctrl_mappings, key=lambda x: severity_order.get(x.finding_severity, 5))
            gaps.append(
                {
                    "framework": worst.framework,
                    "control_id": worst.control_id,
                    "control_name": worst.control_name,
                    "finding_count": len(ctrl_mappings),
                    "worst_severity": worst.finding_severity,
                    "findings": [m.finding_technique for m in ctrl_mappings[:5]],
                }
            )

        # Sort by severity then finding count
        gaps.sort(key=lambda g: (severity_order.get(g["worst_severity"], 5), -g["finding_count"]))
        return gaps
