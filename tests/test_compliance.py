#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for core/compliance.py — Compliance mapping engine."""

import os
import sys
import unittest
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.compliance import (
    ComplianceEngine, ComplianceMapping, ComplianceReport,
    OWASP_TOP_10, PCI_DSS, NIST_800_53, CIS_CONTROLS, SANS_TOP_25_CWES,
)


@dataclass
class MockFinding:
    technique: str = ''
    severity: str = 'MEDIUM'
    cwe_id: str = ''
    cvss: float = 5.0
    url: str = ''
    param: str = ''


class TestComplianceMapping(unittest.TestCase):
    """Test ComplianceMapping dataclass."""

    def test_to_dict(self):
        m = ComplianceMapping(
            finding_technique='SQL Injection',
            finding_severity='HIGH',
            framework='owasp',
            control_id='A03:2021',
            control_name='Injection',
            match_reason='keyword match: sql injection',
        )
        d = m.to_dict()
        self.assertEqual(d['framework'], 'owasp')
        self.assertEqual(d['control_id'], 'A03:2021')


class TestComplianceReport(unittest.TestCase):
    """Test ComplianceReport dataclass."""

    def test_empty_report(self):
        r = ComplianceReport(scan_id='test', total_findings=0)
        d = r.to_dict()
        self.assertEqual(d['total_findings'], 0)
        self.assertEqual(d['mappings'], [])


class TestComplianceEngine(unittest.TestCase):
    """Test ComplianceEngine analysis."""

    def setUp(self):
        self.engine = ComplianceEngine()

    def test_empty_findings(self):
        report = self.engine.analyze([], scan_id='empty')
        self.assertEqual(report.total_findings, 0)
        self.assertEqual(len(report.mappings), 0)

    def test_sqli_maps_to_owasp_a03(self):
        findings = [MockFinding(technique='SQL Injection', severity='HIGH', cwe_id='CWE-89')]
        report = self.engine.analyze(findings, frameworks=['owasp'])
        owasp_mappings = [m for m in report.mappings if m.framework == 'owasp']
        control_ids = {m.control_id for m in owasp_mappings}
        self.assertIn('A03:2021', control_ids)

    def test_xss_maps_to_owasp_a03(self):
        findings = [MockFinding(technique='Cross-Site Scripting (XSS)', severity='MEDIUM', cwe_id='CWE-79')]
        report = self.engine.analyze(findings, frameworks=['owasp'])
        control_ids = {m.control_id for m in report.mappings}
        self.assertIn('A03:2021', control_ids)

    def test_idor_maps_to_owasp_a01(self):
        findings = [MockFinding(technique='IDOR', severity='HIGH')]
        report = self.engine.analyze(findings, frameworks=['owasp'])
        control_ids = {m.control_id for m in report.mappings}
        self.assertIn('A01:2021', control_ids)

    def test_ssrf_maps_to_owasp_a10(self):
        findings = [MockFinding(technique='SSRF', severity='HIGH', cwe_id='CWE-918')]
        report = self.engine.analyze(findings, frameworks=['owasp'])
        control_ids = {m.control_id for m in report.mappings}
        self.assertIn('A10:2021', control_ids)

    def test_deserialization_maps_to_owasp_a08(self):
        findings = [MockFinding(technique='Deserialization', severity='CRITICAL', cwe_id='CWE-502')]
        report = self.engine.analyze(findings, frameworks=['owasp'])
        control_ids = {m.control_id for m in report.mappings}
        self.assertIn('A08:2021', control_ids)

    def test_pci_dss_mapping(self):
        findings = [MockFinding(technique='SQL Injection', severity='HIGH')]
        report = self.engine.analyze(findings, frameworks=['pci_dss'])
        pci_mappings = [m for m in report.mappings if m.framework == 'pci_dss']
        self.assertGreater(len(pci_mappings), 0)

    def test_nist_mapping(self):
        findings = [MockFinding(technique='Brute Force Attack', severity='MEDIUM')]
        report = self.engine.analyze(findings, frameworks=['nist'])
        nist_mappings = [m for m in report.mappings if m.framework == 'nist']
        self.assertGreater(len(nist_mappings), 0)

    def test_cis_mapping(self):
        findings = [MockFinding(technique='XSS Cross-Site Scripting', severity='MEDIUM')]
        report = self.engine.analyze(findings, frameworks=['cis'])
        cis_mappings = [m for m in report.mappings if m.framework == 'cis']
        self.assertGreater(len(cis_mappings), 0)

    def test_sans_top_25_cwe_match(self):
        findings = [MockFinding(technique='SQL Injection', cwe_id='CWE-89', severity='HIGH')]
        report = self.engine.analyze(findings)
        sans_mappings = [m for m in report.mappings if m.framework == 'sans']
        self.assertGreater(len(sans_mappings), 0)

    def test_sans_non_matching_cwe(self):
        findings = [MockFinding(technique='Custom Bug', cwe_id='CWE-999999', severity='LOW')]
        report = self.engine.analyze(findings)
        sans_mappings = [m for m in report.mappings if m.framework == 'sans']
        self.assertEqual(len(sans_mappings), 0)

    def test_framework_scores(self):
        findings = [
            MockFinding(technique='SQL Injection', severity='HIGH', cwe_id='CWE-89'),
            MockFinding(technique='XSS', severity='MEDIUM', cwe_id='CWE-79'),
        ]
        report = self.engine.analyze(findings, frameworks=['owasp'])
        self.assertIn('owasp', report.framework_scores)
        score = report.framework_scores['owasp']
        self.assertIn('score_pct', score)
        self.assertIn('passing', score)
        self.assertIn('failing', score)
        self.assertGreater(score['total_controls'], 0)

    def test_gap_analysis(self):
        findings = [
            MockFinding(technique='SQL Injection', severity='CRITICAL'),
            MockFinding(technique='XSS', severity='HIGH'),
            MockFinding(technique='IDOR', severity='HIGH'),
        ]
        report = self.engine.analyze(findings, frameworks=['owasp'])
        self.assertGreater(len(report.gaps), 0)
        # Gaps should be sorted by severity (CRITICAL first)
        if len(report.gaps) > 1:
            sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
            for i in range(len(report.gaps) - 1):
                a = sev_order.get(report.gaps[i]['worst_severity'], 5)
                b = sev_order.get(report.gaps[i + 1]['worst_severity'], 5)
                self.assertLessEqual(a, b)

    def test_all_frameworks(self):
        findings = [MockFinding(technique='SQL Injection', severity='HIGH', cwe_id='CWE-89')]
        report = self.engine.analyze(findings)
        # Should have mappings from multiple frameworks
        frameworks = {m.framework for m in report.mappings}
        self.assertGreater(len(frameworks), 1)

    def test_multiple_findings_same_control(self):
        findings = [
            MockFinding(technique='SQL Injection (MySQL)', severity='HIGH'),
            MockFinding(technique='SQL Injection (PostgreSQL)', severity='CRITICAL'),
        ]
        report = self.engine.analyze(findings, frameworks=['owasp'])
        a03_mappings = [m for m in report.mappings if m.control_id == 'A03:2021']
        self.assertGreaterEqual(len(a03_mappings), 2)

    def test_score_100_when_no_findings(self):
        report = self.engine.analyze([], frameworks=['owasp'])
        if 'owasp' in report.framework_scores:
            self.assertEqual(report.framework_scores['owasp']['score_pct'], 100.0)

    def test_report_to_dict(self):
        findings = [MockFinding(technique='SQL Injection', severity='HIGH')]
        report = self.engine.analyze(findings, scan_id='test-123', target='https://example.com')
        d = report.to_dict()
        self.assertEqual(d['scan_id'], 'test-123')
        self.assertEqual(d['target'], 'https://example.com')
        self.assertIsInstance(d['mappings'], list)


class TestComplianceFrameworkData(unittest.TestCase):
    """Test that compliance framework mappings have correct structure."""

    def test_owasp_has_10_categories(self):
        self.assertEqual(len(OWASP_TOP_10), 10)

    def test_owasp_all_have_keywords(self):
        for key, ctrl in OWASP_TOP_10.items():
            self.assertIn('keywords', ctrl, f'{key} missing keywords')
            self.assertGreater(len(ctrl['keywords']), 0)

    def test_owasp_all_have_cwe_ids(self):
        for key, ctrl in OWASP_TOP_10.items():
            self.assertIn('cwe_ids', ctrl, f'{key} missing cwe_ids')

    def test_pci_dss_structure(self):
        for key, ctrl in PCI_DSS.items():
            self.assertIn('name', ctrl)
            self.assertIn('keywords', ctrl)

    def test_nist_structure(self):
        for key, ctrl in NIST_800_53.items():
            self.assertIn('name', ctrl)
            self.assertIn('keywords', ctrl)

    def test_cis_structure(self):
        for key, ctrl in CIS_CONTROLS.items():
            self.assertIn('name', ctrl)
            self.assertIn('keywords', ctrl)

    def test_sans_top_25_count(self):
        self.assertEqual(len(SANS_TOP_25_CWES), 25)


if __name__ == '__main__':
    unittest.main()
