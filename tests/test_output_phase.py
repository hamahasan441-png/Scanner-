#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for Phase 10 — Commit & Report.

Tests:
  - OutputPhase orchestrator (DB commit + report generation)
  - Database.save_results / save_chains / ExploitChainModel
  - ReportGenerator Phase 10 enrichment sections
    (executive_summary, exploit_chains, waf_bypass_disclosure,
     origin_exposure_note, remediation_plan, agent_reasoning_log)
"""

import json
import os
import tempfile
import unittest
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List
from unittest.mock import MagicMock, patch, PropertyMock


# ── Test data ─────────────────────────────────────────────────────────

@dataclass
class FakeFinding:
    technique: str = ''
    url: str = ''
    method: str = 'GET'
    param: str = ''
    payload: str = ''
    evidence: str = ''
    severity: str = 'HIGH'
    confidence: float = 0.9
    mitre_id: str = ''
    cwe_id: str = ''
    cvss: float = 8.0
    extracted_data: str = ''
    signals: dict = field(default_factory=dict)
    priority: float = 0.0
    remediation: str = ''


@dataclass
class FakeChain:
    id: str = 'CHAIN-001'
    name: str = 'XSS + No HttpOnly → Session Hijack'
    steps: list = field(default_factory=lambda: ['xss', 'missing httponly'])
    combined_cvss: float = 8.5
    combined_severity: str = 'HIGH'
    findings: list = field(default_factory=list)


def _sample_findings():
    return [
        FakeFinding(
            technique='SQL Injection',
            url='http://example.com/page?id=1',
            param='id',
            payload="' OR 1=1 --",
            evidence='MySQL syntax error',
            severity='CRITICAL',
            confidence=0.95,
            mitre_id='T1190',
            cwe_id='CWE-89',
            cvss=9.1,
            remediation='Use parameterized queries',
            signals={'waf_flag': 'WAF_BYPASSED_CONFIRMED', 'stability': 'STABLE'},
        ),
        FakeFinding(
            technique='XSS',
            url='http://example.com/search?q=test',
            param='q',
            payload='<script>alert(1)</script>',
            evidence='<script>alert(1)</script>',
            severity='MEDIUM',
            confidence=0.8,
            cvss=6.1,
            remediation='Encode output properly',
        ),
        FakeFinding(
            technique='Missing Security Header',
            url='http://example.com/',
            severity='INFO',
            cvss=0.0,
            remediation='Add HSTS header',
        ),
    ]


def _sample_chains():
    return [
        FakeChain(),
        FakeChain(
            id='CHAIN-002',
            name='SSRF → Internal Pivot',
            steps=['ssrf'],
            combined_cvss=9.5,
            combined_severity='CRITICAL',
        ),
    ]


def _sample_shield():
    return {
        'cdn': {'detected': True, 'provider': 'Cloudflare'},
        'waf': {'detected': True, 'provider': 'Cloudflare WAF'},
        'needs_waf_bypass': True,
        'needs_origin_discovery': True,
    }


def _sample_origin():
    return {
        'origin_ip': '93.184.216.34',
        'confidence': 0.85,
        'method': 'subdomain_leak',
        'all_candidates': [{'ip': '93.184.216.34'}],
    }


def _sample_agent():
    return {
        'goals_completed': ['Test XSS on search', 'Enumerate admin endpoints'],
        'goals_skipped': ['DNS zone transfer'],
        'pivots_found': ['Internal API at /internal/v1'],
        'scan_coverage_pct': 72,
    }


def _mock_engine(findings=None, tmpdir=None):
    """Create a mock engine with realistic attributes."""
    engine = MagicMock()
    engine.scan_id = 'test-ph10'
    engine.target = 'http://example.com'
    engine.start_time = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    engine.end_time = datetime(2024, 6, 1, 12, 10, 0, tzinfo=timezone.utc)
    engine.findings = findings or _sample_findings()
    engine.config = {'verbose': False, 'output_dir': tmpdir or '/tmp', 'format': 'html'}
    engine.requester = MagicMock()
    engine.requester.total_requests = 500
    engine.db = MagicMock()
    engine.emit_pipeline_event = MagicMock()
    engine._shield_profile = None
    engine._exploit_chains = []
    engine._origin_result = None
    engine._agent_result = None
    return engine


# ──────────────────────────────────────────────────────────────────────
# OutputPhase Tests
# ──────────────────────────────────────────────────────────────────────

class TestOutputPhaseInit(unittest.TestCase):

    def test_init(self):
        from core.output_phase import OutputPhase
        engine = _mock_engine()
        op = OutputPhase(engine)
        self.assertIs(op.engine, engine)
        self.assertIs(op.db, engine.db)

    def test_init_no_db(self):
        from core.output_phase import OutputPhase
        engine = _mock_engine()
        engine.db = None
        op = OutputPhase(engine)
        self.assertIsNone(op.db)


class TestOutputPhaseRun(unittest.TestCase):

    def test_run_returns_summary(self):
        from core.output_phase import OutputPhase
        with tempfile.TemporaryDirectory() as td:
            engine = _mock_engine(tmpdir=td)
            op = OutputPhase(engine)
            result = op.run(
                verified_findings=_sample_findings(),
                exploit_chains=_sample_chains(),
                shield_profile=_sample_shield(),
                origin_result=_sample_origin(),
                agent_result=_sample_agent(),
            )
            self.assertIn('findings_committed', result)
            self.assertIn('chains_committed', result)
            self.assertIn('reports', result)
            self.assertEqual(result['findings_committed'], 3)
            self.assertEqual(result['chains_committed'], 2)

    def test_run_emits_pipeline_events(self):
        from core.output_phase import OutputPhase
        with tempfile.TemporaryDirectory() as td:
            engine = _mock_engine(tmpdir=td)
            op = OutputPhase(engine)
            op.run(verified_findings=[])
            calls = [c[0][0] for c in engine.emit_pipeline_event.call_args_list]
            self.assertIn('phase10_start', calls)
            self.assertIn('phase10_complete', calls)

    def test_run_calls_db_save_results(self):
        from core.output_phase import OutputPhase
        with tempfile.TemporaryDirectory() as td:
            engine = _mock_engine(tmpdir=td)
            findings = _sample_findings()
            op = OutputPhase(engine)
            op.run(verified_findings=findings)
            engine.db.save_results.assert_called_once_with('test-ph10', findings)

    def test_run_calls_db_save_chains(self):
        from core.output_phase import OutputPhase
        with tempfile.TemporaryDirectory() as td:
            engine = _mock_engine(tmpdir=td)
            chains = _sample_chains()
            op = OutputPhase(engine)
            op.run(verified_findings=[], exploit_chains=chains)
            engine.db.save_chains.assert_called_once_with('test-ph10', chains)

    def test_run_calls_db_update_scan(self):
        from core.output_phase import OutputPhase
        with tempfile.TemporaryDirectory() as td:
            engine = _mock_engine(tmpdir=td)
            op = OutputPhase(engine)
            op.run(verified_findings=_sample_findings())
            engine.db.update_scan.assert_called_once()
            call_kwargs = engine.db.update_scan.call_args
            self.assertEqual(call_kwargs[0][0], 'test-ph10')

    def test_run_no_db_graceful(self):
        from core.output_phase import OutputPhase
        with tempfile.TemporaryDirectory() as td:
            engine = _mock_engine(tmpdir=td)
            engine.db = None
            op = OutputPhase(engine)
            result = op.run(verified_findings=[])
            self.assertEqual(result['findings_committed'], 0)

    def test_run_generates_reports(self):
        from core.output_phase import OutputPhase
        with tempfile.TemporaryDirectory() as td:
            engine = _mock_engine(tmpdir=td)
            op = OutputPhase(engine)
            result = op.run(verified_findings=_sample_findings(), report_format='json')
            self.assertIn('json', result['reports'])
            # JSON file should exist
            json_path = result['reports']['json']
            self.assertTrue(os.path.isfile(json_path))

    def test_run_all_formats(self):
        from core.output_phase import OutputPhase
        with tempfile.TemporaryDirectory() as td:
            engine = _mock_engine(tmpdir=td)
            op = OutputPhase(engine)
            result = op.run(verified_findings=_sample_findings(), report_format='all')
            # At least html, json, csv, txt should be present
            for fmt in ['html', 'json', 'csv', 'txt']:
                self.assertIn(fmt, result['reports'])

    def test_run_defaults_to_engine_findings(self):
        from core.output_phase import OutputPhase
        with tempfile.TemporaryDirectory() as td:
            engine = _mock_engine(tmpdir=td)
            op = OutputPhase(engine)
            result = op.run()
            self.assertEqual(result['findings_committed'], len(engine.findings))


# ──────────────────────────────────────────────────────────────────────
# Database Enhancement Tests
# ──────────────────────────────────────────────────────────────────────

class TestDatabaseSaveResults(unittest.TestCase):

    def test_save_results_bulk(self):
        """save_results should commit all findings in one batch."""
        from utils.database import Database, SQLALCHEMY_AVAILABLE
        if not SQLALCHEMY_AVAILABLE:
            self.skipTest('sqlalchemy not available')

        db = Database()
        findings = _sample_findings()
        db.save_scan(scan_id='bulk-test', target='http://example.com')
        db.save_results('bulk-test', findings)
        # No exception → success (we don't query back in unit test)


class TestDatabaseSaveChains(unittest.TestCase):

    def test_save_chains(self):
        """save_chains should persist exploit chain records."""
        from utils.database import Database, SQLALCHEMY_AVAILABLE
        if not SQLALCHEMY_AVAILABLE:
            self.skipTest('sqlalchemy not available')

        db = Database()
        chains = _sample_chains()
        db.save_scan(scan_id='chain-test', target='http://example.com')
        db.save_chains('chain-test', chains)


class TestExploitChainModel(unittest.TestCase):

    def test_model_exists(self):
        from utils.database import ExploitChainModel
        self.assertTrue(hasattr(ExploitChainModel, '__tablename__'))


# ──────────────────────────────────────────────────────────────────────
# ReportGenerator Phase 10 Enrichment Tests
# ──────────────────────────────────────────────────────────────────────

def _make_gen(findings=None, chains=None, shield=None, origin=None, agent=None, output_dir=None):
    """Create a ReportGenerator with Phase 10 data."""
    from core.reporter import ReportGenerator
    with patch.object(ReportGenerator, '_load_from_db'):
        return ReportGenerator(
            scan_id='ph10-test',
            findings=findings if findings is not None else _sample_findings(),
            target='http://example.com',
            start_time=datetime(2024, 6, 1, 12, 0, 0),
            end_time=datetime(2024, 6, 1, 12, 10, 0),
            total_requests=500,
            output_dir=output_dir,
            exploit_chains=chains or [],
            shield_profile=shield or {},
            origin_result=origin or {},
            agent_result=agent or {},
        )


class TestReporterNewParams(unittest.TestCase):

    def test_accepts_new_params(self):
        gen = _make_gen(chains=_sample_chains(), shield=_sample_shield())
        self.assertEqual(len(gen.exploit_chains), 2)
        self.assertTrue(gen.shield_profile.get('waf', {}).get('detected'))

    def test_defaults_to_empty(self):
        gen = _make_gen()
        self.assertEqual(gen.exploit_chains, [])
        self.assertEqual(gen.shield_profile, {})
        self.assertEqual(gen.origin_result, {})
        self.assertEqual(gen.agent_result, {})


class TestSeverityCounts(unittest.TestCase):

    def test_counts(self):
        gen = _make_gen()
        counts = gen._severity_counts()
        self.assertEqual(counts.get('CRITICAL'), 1)
        self.assertEqual(counts.get('MEDIUM'), 1)
        self.assertEqual(counts.get('INFO'), 1)

    def test_empty(self):
        gen = _make_gen(findings=[])
        self.assertEqual(gen._severity_counts(), {})


class TestTopCriticalRisks(unittest.TestCase):

    def test_returns_top_n(self):
        gen = _make_gen()
        top = gen._top_critical_risks(2)
        self.assertEqual(len(top), 2)
        self.assertGreaterEqual(top[0].get('cvss', 0), top[1].get('cvss', 0))


class TestGetChainsData(unittest.TestCase):

    def test_with_objects(self):
        gen = _make_gen(chains=_sample_chains())
        data = gen._get_chains_data()
        self.assertEqual(len(data), 2)
        self.assertEqual(data[0]['id'], 'CHAIN-001')

    def test_with_dicts(self):
        gen = _make_gen(chains=[{'id': 'C1', 'name': 'test', 'steps': []}])
        data = gen._get_chains_data()
        self.assertEqual(data[0]['id'], 'C1')

    def test_empty(self):
        gen = _make_gen(chains=[])
        self.assertEqual(gen._get_chains_data(), [])


class TestWafBypassInfo(unittest.TestCase):

    def test_waf_detected(self):
        gen = _make_gen(shield=_sample_shield())
        info = gen._waf_bypass_info()
        self.assertTrue(info['waf_detected'])
        self.assertEqual(info['waf_provider'], 'Cloudflare WAF')

    def test_bypass_extracted(self):
        findings = _sample_findings()
        findings[0].signals = {'waf_flag': 'WAF_BYPASSED_CONFIRMED'}
        gen = _make_gen(findings=findings, shield=_sample_shield())
        info = gen._waf_bypass_info()
        self.assertEqual(len(info['bypasses']), 1)
        self.assertEqual(info['bypasses'][0]['technique'], 'SQL Injection')

    def test_no_waf(self):
        gen = _make_gen(shield={})
        info = gen._waf_bypass_info()
        self.assertFalse(info.get('waf_detected'))


class TestOriginExposureInfo(unittest.TestCase):

    def test_with_origin(self):
        gen = _make_gen(origin=_sample_origin(), shield=_sample_shield())
        info = gen._origin_exposure_info()
        self.assertEqual(info['origin_ip'], '93.184.216.34')
        self.assertEqual(info['cdn_provider'], 'Cloudflare')
        self.assertTrue(info['cdn_misconfigured'])

    def test_no_origin(self):
        gen = _make_gen()
        info = gen._origin_exposure_info()
        self.assertIsNone(info.get('origin_ip'))


class TestAgentReasoningLog(unittest.TestCase):

    def test_with_agent(self):
        gen = _make_gen(agent=_sample_agent())
        log = gen._agent_reasoning_log()
        self.assertEqual(len(log), 3)  # 2 goals + 1 pivot
        types = [e['type'] for e in log]
        self.assertIn('goal_completed', types)
        self.assertIn('pivot', types)

    def test_no_agent(self):
        gen = _make_gen()
        self.assertEqual(gen._agent_reasoning_log(), [])


class TestRemediationPlan(unittest.TestCase):

    def test_sorted_by_cvss(self):
        gen = _make_gen()
        plan = gen._remediation_plan()
        self.assertGreater(len(plan), 0)
        # First item should be highest CVSS
        self.assertEqual(plan[0]['technique'], 'SQL Injection')

    def test_dedup(self):
        findings = [
            FakeFinding(technique='XSS', cvss=6.1, remediation='Encode output'),
            FakeFinding(technique='XSS', url='http://example.com/other', cvss=6.1, remediation='Encode output'),
        ]
        gen = _make_gen(findings=findings)
        plan = gen._remediation_plan()
        self.assertEqual(len(plan), 1)

    def test_empty(self):
        gen = _make_gen(findings=[FakeFinding(technique='Test', remediation='')])
        self.assertEqual(gen._remediation_plan(), [])


# ──────────────────────────────────────────────────────────────────────
# Report Format Generation Tests (Phase 10 sections)
# ──────────────────────────────────────────────────────────────────────

class TestJsonReport(unittest.TestCase):

    def test_json_has_phase10_sections(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_gen(
                chains=_sample_chains(),
                shield=_sample_shield(),
                origin=_sample_origin(),
                agent=_sample_agent(),
                output_dir=td,
            )
            path = gen.generate('json')
            self.assertIsNotNone(path)

            with open(path) as f:
                data = json.load(f)

            self.assertIn('executive_summary', data)
            self.assertIn('exploit_chains', data)
            self.assertIn('waf_bypass_disclosure', data)
            self.assertIn('origin_exposure_note', data)
            self.assertIn('remediation_plan', data)
            self.assertIn('agent_reasoning_log', data)

    def test_json_executive_summary(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_gen(origin=_sample_origin(), output_dir=td)
            path = gen.generate('json')
            with open(path) as f:
                data = json.load(f)

            summary = data['executive_summary']
            self.assertIn('severity_counts', summary)
            self.assertIn('top_critical_risks', summary)
            self.assertIn('origin_exposure', summary)

    def test_json_chains_populated(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_gen(chains=_sample_chains(), output_dir=td)
            path = gen.generate('json')
            with open(path) as f:
                data = json.load(f)

            self.assertEqual(len(data['exploit_chains']), 2)
            self.assertEqual(data['exploit_chains'][0]['name'], 'XSS + No HttpOnly → Session Hijack')


class TestHtmlReport(unittest.TestCase):

    def test_html_has_new_sections(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_gen(
                chains=_sample_chains(),
                shield=_sample_shield(),
                origin=_sample_origin(),
                agent=_sample_agent(),
                output_dir=td,
            )
            path = gen.generate('html')
            self.assertIsNotNone(path)

            with open(path) as f:
                content = f.read()

            self.assertIn('Executive Summary', content)
            self.assertIn('Exploit Chains', content)
            self.assertIn('WAF Bypass Disclosure', content)
            self.assertIn('Remediation Plan', content)
            self.assertIn('Agent Reasoning Log', content)

    def test_html_origin_exposure(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_gen(origin=_sample_origin(), shield=_sample_shield(), output_dir=td)
            path = gen.generate('html')
            with open(path) as f:
                content = f.read()
            self.assertIn('93.184.216.34', content)
            self.assertIn('Cloudflare', content)

    def test_html_severity_cards(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_gen(output_dir=td)
            path = gen.generate('html')
            with open(path) as f:
                content = f.read()
            self.assertIn('CRITICAL', content)


class TestTxtReport(unittest.TestCase):

    def test_txt_has_new_sections(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_gen(
                chains=_sample_chains(),
                shield=_sample_shield(),
                origin=_sample_origin(),
                agent=_sample_agent(),
                output_dir=td,
            )
            path = gen.generate('txt')
            self.assertIsNotNone(path)

            with open(path) as f:
                content = f.read()

            self.assertIn('EXECUTIVE SUMMARY', content)
            self.assertIn('EXPLOIT CHAINS', content)
            self.assertIn('WAF BYPASS DISCLOSURE', content)
            self.assertIn('REMEDIATION PLAN', content)
            self.assertIn('AGENT REASONING LOG', content)

    def test_txt_origin_exposure(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_gen(origin=_sample_origin(), output_dir=td)
            path = gen.generate('txt')
            with open(path) as f:
                content = f.read()
            self.assertIn('93.184.216.34', content)


class TestXmlReport(unittest.TestCase):

    def test_xml_has_chains(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_gen(chains=_sample_chains(), output_dir=td)
            path = gen.generate('xml')
            self.assertIsNotNone(path)

            with open(path) as f:
                content = f.read()

            self.assertIn('<exploit-chains>', content)
            self.assertIn('CHAIN-001', content)
            self.assertIn('CHAIN-002', content)

    def test_xml_no_chains(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_gen(output_dir=td)
            path = gen.generate('xml')
            with open(path) as f:
                content = f.read()
            self.assertNotIn('<exploit-chains>', content)


class TestPdfReport(unittest.TestCase):

    def test_pdf_with_chains(self):
        try:
            import fpdf  # noqa: F401
        except ImportError:
            self.skipTest('fpdf2 not installed')

        with tempfile.TemporaryDirectory() as td:
            gen = _make_gen(chains=_sample_chains(), origin=_sample_origin(), output_dir=td)
            path = gen.generate('pdf')
            self.assertIsNotNone(path)
            self.assertTrue(os.path.isfile(path))


class TestCsvReport(unittest.TestCase):

    def test_csv_generates(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_gen(output_dir=td)
            path = gen.generate('csv')
            self.assertIsNotNone(path)
            with open(path) as f:
                content = f.read()
            self.assertIn('SQL Injection', content)


class TestSarifReport(unittest.TestCase):

    def test_sarif_generates(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_gen(output_dir=td)
            path = gen.generate('sarif')
            self.assertIsNotNone(path)
            with open(path) as f:
                data = json.load(f)
            self.assertEqual(data['version'], '2.1.0')


if __name__ == '__main__':
    unittest.main()
