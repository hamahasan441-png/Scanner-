#!/usr/bin/env python3
"""Tests for core/post_worker_verifier.py — Phase 9 Post-Worker Verification"""
import sys
import os
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _mock_engine():
    e = MagicMock()
    e.config = {'verbose': False}
    e.requester = MagicMock()
    e.requester.request.return_value = None
    e.findings = []
    e.emit_pipeline_event = MagicMock()
    e._shield_profile = None
    return e


def _mock_finding(technique='SQL Injection', url='http://a.com', param='id',
                  payload="' OR 1=1--", evidence='SQL error', severity='HIGH',
                  confidence=0.8, cvss=0.0, method='GET'):
    f = MagicMock()
    f.technique = technique
    f.url = url
    f.param = param
    f.payload = payload
    f.evidence = evidence
    f.severity = severity
    f.confidence = confidence
    f.cvss = cvss
    f.method = method
    f.signals = {}
    return f


class TestExploitChain(unittest.TestCase):
    def test_creation(self):
        from core.post_worker_verifier import ExploitChain
        c = ExploitChain(id='CHAIN-001', name='Test Chain', combined_cvss=9.5)
        self.assertEqual(c.id, 'CHAIN-001')
        self.assertEqual(c.combined_cvss, 9.5)

    def test_to_dict(self):
        from core.post_worker_verifier import ExploitChain
        c = ExploitChain(id='CHAIN-001', name='Test', steps=['sqli', 'rce'], combined_cvss=9.0)
        d = c.to_dict()
        self.assertEqual(d['id'], 'CHAIN-001')
        self.assertEqual(d['steps'], ['sqli', 'rce'])


class TestVerificationResult(unittest.TestCase):
    def test_to_dict(self):
        from core.post_worker_verifier import VerificationResult
        r = VerificationResult()
        r.verified_findings = [_mock_finding()]
        d = r.to_dict()
        self.assertEqual(d['verified_count'], 1)


class TestChainDetector(unittest.TestCase):
    def setUp(self):
        from core.post_worker_verifier import ChainDetector
        self.detector = ChainDetector(_mock_engine())

    def test_analyze_empty(self):
        result = self.detector.analyze([])
        self.assertEqual(len(result), 0)

    def test_detect_xss_httponly_chain(self):
        findings = [
            _mock_finding(technique='XSS Reflected', severity='HIGH'),
            _mock_finding(technique='Missing HttpOnly Flag on Cookie', severity='LOW'),
        ]
        chains = self.detector.analyze(findings)
        chain_names = [c.name for c in chains]
        self.assertIn('XSS + No HttpOnly → Session Hijack', chain_names)

    def test_detect_ssrf_internal(self):
        findings = [
            _mock_finding(technique='SSRF', evidence='internal service response at 169.254.169.254'),
        ]
        chains = self.detector.analyze(findings)
        chain_names = [c.name for c in chains]
        self.assertIn('SSRF → Internal Pivot', chain_names)

    def test_detect_cors_credentials(self):
        findings = [
            _mock_finding(technique='CORS Misconfiguration', evidence='Access-Control-Allow-Credentials: true'),
        ]
        chains = self.detector.analyze(findings)
        chain_names = [c.name for c in chains]
        self.assertIn('CORS + Credentials → Cross-Origin Data Theft', chain_names)


class TestPostWorkerVerifier(unittest.TestCase):
    def setUp(self):
        from core.post_worker_verifier import PostWorkerVerifier
        self.verifier = PostWorkerVerifier(_mock_engine())

    def test_run_empty(self):
        result = self.verifier.run([])
        self.assertEqual(len(result.verified_findings), 0)
        self.assertEqual(result.stats['input'], 0)

    def test_url_level_findings_pass(self):
        f = _mock_finding(param='', payload='')
        result = self.verifier.run([f])
        # URL-level findings pass recheck by default
        self.assertGreater(len(result.verified_findings), 0)

    def test_cvss_scoring(self):
        f = _mock_finding(technique='SQL Injection', param='', payload='')
        f.cvss = 0.0
        result = self.verifier.run([f])
        # CVSS should be auto-scored
        for finding in result.verified_findings:
            self.assertGreater(finding.cvss, 0)

    def test_severity_from_cvss(self):
        self.assertEqual(self.verifier._cvss_to_severity(9.5), 'CRITICAL')
        self.assertEqual(self.verifier._cvss_to_severity(8.0), 'HIGH')
        self.assertEqual(self.verifier._cvss_to_severity(5.0), 'MEDIUM')
        self.assertEqual(self.verifier._cvss_to_severity(2.0), 'LOW')
        self.assertEqual(self.verifier._cvss_to_severity(0.0), 'INFO')

    def test_compute_cvss(self):
        f = _mock_finding(technique='SQL Injection')
        self.assertEqual(self.verifier._compute_cvss(f), 8.1)

    def test_compute_cvss_xss(self):
        f = _mock_finding(technique='XSS Reflected')
        self.assertEqual(self.verifier._compute_cvss(f), 6.1)

    def test_compute_cvss_cmdi(self):
        f = _mock_finding(technique='Command Injection')
        self.assertEqual(self.verifier._compute_cvss(f), 9.8)

    def test_structural_endpoint(self):
        result = self.verifier._structural_endpoint('http://example.com/user/123/profile')
        self.assertIn('{N}', result)

    def test_step4_deduplicate(self):
        f1 = _mock_finding(technique='SQLi', url='http://a.com/user/1', param='id', confidence=0.8)
        f2 = _mock_finding(technique='SQLi', url='http://a.com/user/2', param='id', confidence=0.6)
        stats = {'deduplicated': 0}
        result = self.verifier._step4_deduplicate([f1, f2], stats)
        self.assertEqual(len(result), 1)
        self.assertGreater(stats['deduplicated'], 0)

    def test_waf_check_annotates(self):
        engine = _mock_engine()
        engine._shield_profile = {'waf': {'detected': True}, 'needs_waf_bypass': True}
        from core.post_worker_verifier import PostWorkerVerifier
        v = PostWorkerVerifier(engine)
        f = _mock_finding()
        result = v._step3_waf_check([f])
        self.assertEqual(result[0].signals.get('waf_flag'), 'BYPASS_REQUIRED')

    def test_fp_filter_low_confidence_xss(self):
        f = _mock_finding(technique='XSS', confidence=0.3)
        stats = {'fp_filtered': 0}
        result = self.verifier._step2_fp_filter([f], stats)
        self.assertEqual(len(result), 0)
        self.assertEqual(stats['fp_filtered'], 1)

    def test_fp_filter_high_confidence_passes(self):
        f = _mock_finding(technique='XSS', confidence=0.9)
        stats = {'fp_filtered': 0}
        result = self.verifier._step2_fp_filter([f], stats)
        self.assertEqual(len(result), 1)


class TestCheckEvidence(unittest.TestCase):
    def setUp(self):
        from core.post_worker_verifier import PostWorkerVerifier
        self.verifier = PostWorkerVerifier(_mock_engine())

    def test_time_based_evidence(self):
        f = _mock_finding(technique='Time-based SQLi')
        resp = MagicMock()
        resp.text = 'ok'
        self.assertTrue(self.verifier._check_evidence(f, resp, 5.0))
        self.assertFalse(self.verifier._check_evidence(f, resp, 1.0))

    def test_error_based_evidence(self):
        f = _mock_finding(technique='Error-based SQLi')
        resp = MagicMock()
        resp.text = 'You have an SQL syntax error near...'
        self.assertTrue(self.verifier._check_evidence(f, resp, 0.5))

    def test_xss_evidence(self):
        f = _mock_finding(technique='Reflected XSS', payload='<script>alert(1)</script>')
        resp = MagicMock()
        resp.text = 'Hello <script>alert(1)</script> World'
        self.assertTrue(self.verifier._check_evidence(f, resp, 0.5))

    def test_ssti_evidence(self):
        f = _mock_finding(technique='SSTI Jinja2')
        resp = MagicMock()
        resp.text = 'Result: 49'
        self.assertTrue(self.verifier._check_evidence(f, resp, 0.5))

    def test_lfi_evidence(self):
        f = _mock_finding(technique='LFI')
        resp = MagicMock()
        resp.text = 'root:x:0:0:root:/root:/bin/bash'
        self.assertTrue(self.verifier._check_evidence(f, resp, 0.5))

    def test_cmdi_evidence(self):
        f = _mock_finding(technique='Command Injection')
        resp = MagicMock()
        resp.text = 'uid=0(root) gid=0(root)'
        self.assertTrue(self.verifier._check_evidence(f, resp, 0.5))


if __name__ == '__main__':
    unittest.main()
