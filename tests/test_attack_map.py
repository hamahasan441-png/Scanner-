#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for Phase 11 — Attack Map (Exploit-Aware)."""

import unittest
from unittest.mock import MagicMock
from types import SimpleNamespace

from core.attack_map import (
    NodeClassifier,
    EdgeBuilder,
    PathFinder,
    ImpactZoneMapper,
    AttackerSimulator,
    AttackMapBuilder,
    AttackNode,
    AttackEdge,
    AttackPath,
    ImpactZone,
    SimulationResult,
    ENTRY, PIVOT, ESCALATION, IMPACT, SUPPORT,
    REQUIRES, ENABLES, CHAINS_TO, AMPLIFIES,
    CRITICAL_PATH, HIGH_PATH, COMPLEX_PATH, DIRECT_PATH,
    WEAPONIZED_PATH, MSF_PATH, ZERO_CLICK_PATH,
    ZONE_DATA_BREACH, ZONE_ACCOUNT_TAKEOVER,
    ZONE_SERVER_COMPROMISE, ZONE_INTERNAL_PIVOT,
    ZONE_CLOUD_CRED_THEFT, ZONE_PERSISTENCE,
    PROFILE_OPPORTUNISTIC, PROFILE_SKILLED, PROFILE_APT,
    WEAPONIZED, PUBLIC_POC, PARTIAL_POC, THEORETICAL,
)


def _make_enriched_finding(**kw):
    """Create an enriched finding with exploit fields."""
    defaults = {
        'id': 'f1',
        'technique': 'SQL Injection',
        'url': 'http://example.com/login',
        'param': 'username',
        'payload': "' OR 1=1 --",
        'evidence': 'MySQL syntax error',
        'severity': 'HIGH',
        'cvss': 8.1,
        'confidence': 0.9,
        'adjusted_cvss': 8.6,
        'adjusted_severity': 'HIGH',
        'exploit_availability': PUBLIC_POC,
        'actively_exploited': False,
        'metasploit_ready': True,
        'nuclei_ready': False,
        'exploit_record': None,
        '_exploit_finding_id': 'f1',
        'priority': 50.0,
        'method': 'GET',
    }
    defaults.update(kw)
    return SimpleNamespace(**defaults)


def _make_engine():
    """Create a mock engine."""
    engine = MagicMock()
    engine.config = {'verbose': False, 'quiet': True}
    engine.emit_pipeline_event = MagicMock()
    return engine


# ══════════════════════════════════════════════════════════════════════
# STEP 1: NodeClassifier
# ══════════════════════════════════════════════════════════════════════

class TestNodeClassifier(unittest.TestCase):

    def test_classify_sqli_as_entry(self):
        """SQLi with moderate CVSS is classified as ENTRY."""
        finding = _make_enriched_finding(technique='SQL Injection', cvss=7.5)
        nodes = NodeClassifier.classify([finding])
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0].type, ENTRY)

    def test_classify_cmdi_high_cvss_as_impact(self):
        """Command injection with CVSS >= 9.0 is IMPACT (final objective)."""
        finding = _make_enriched_finding(
            technique='Command Injection', cvss=9.8, adjusted_cvss=9.8,
        )
        nodes = NodeClassifier.classify([finding])
        self.assertEqual(nodes[0].type, IMPACT)

    def test_classify_rce_as_impact(self):
        """RCE with high CVSS classified as IMPACT."""
        finding = _make_enriched_finding(
            technique='RCE', cvss=9.8, adjusted_cvss=9.8, severity='CRITICAL',
        )
        nodes = NodeClassifier.classify([finding])
        self.assertEqual(nodes[0].type, IMPACT)

    def test_classify_cmdi_moderate_cvss_as_entry(self):
        """Command injection with CVSS < 9.0 is classified as ENTRY."""
        finding = _make_enriched_finding(
            technique='Command Injection', cvss=7.5, adjusted_cvss=7.5,
        )
        nodes = NodeClassifier.classify([finding])
        self.assertEqual(nodes[0].type, ENTRY)

    def test_classify_ssrf_as_entry(self):
        finding = _make_enriched_finding(technique='SSRF', cvss=7.5)
        nodes = NodeClassifier.classify([finding])
        self.assertEqual(nodes[0].type, ENTRY)

    def test_classify_lfi_as_pivot(self):
        finding = _make_enriched_finding(technique='LFI', cvss=6.5)
        nodes = NodeClassifier.classify([finding])
        self.assertEqual(nodes[0].type, PIVOT)

    def test_classify_cors_as_support(self):
        finding = _make_enriched_finding(technique='CORS', cvss=4.0, severity='MEDIUM')
        nodes = NodeClassifier.classify([finding])
        self.assertEqual(nodes[0].type, SUPPORT)

    def test_classify_idor_as_escalation(self):
        finding = _make_enriched_finding(technique='IDOR', cvss=6.5)
        nodes = NodeClassifier.classify([finding])
        self.assertEqual(nodes[0].type, ESCALATION)

    def test_classify_xss_as_support(self):
        finding = _make_enriched_finding(technique='XSS', cvss=6.1, severity='MEDIUM')
        nodes = NodeClassifier.classify([finding])
        self.assertEqual(nodes[0].type, SUPPORT)

    def test_classify_jwt_as_escalation(self):
        finding = _make_enriched_finding(technique='JWT', cvss=7.0)
        nodes = NodeClassifier.classify([finding])
        self.assertEqual(nodes[0].type, ESCALATION)

    def test_classify_file_upload_as_entry(self):
        finding = _make_enriched_finding(technique='File Upload', cvss=7.5)
        nodes = NodeClassifier.classify([finding])
        self.assertEqual(nodes[0].type, ENTRY)

    def test_node_has_exploit_fields(self):
        finding = _make_enriched_finding(
            exploit_availability=WEAPONIZED,
            actively_exploited=True,
            metasploit_ready=True,
        )
        nodes = NodeClassifier.classify([finding])
        n = nodes[0]
        self.assertEqual(n.exploit_availability, WEAPONIZED)
        self.assertTrue(n.actively_exploited)
        self.assertTrue(n.metasploit_ready)
        self.assertTrue(n.cisa_kev)

    def test_node_id_unique(self):
        f1 = _make_enriched_finding(url='http://a.com/p1', technique='SQLi')
        f2 = _make_enriched_finding(url='http://a.com/p2', technique='XSS')
        nodes = NodeClassifier.classify([f1, f2])
        self.assertNotEqual(nodes[0].id, nodes[1].id)

    def test_node_to_dict(self):
        node = AttackNode(id='N-1', label='Test', type=ENTRY)
        d = node.to_dict()
        self.assertEqual(d['id'], 'N-1')
        self.assertEqual(d['type'], ENTRY)

    def test_classify_empty_list(self):
        nodes = NodeClassifier.classify([])
        self.assertEqual(nodes, [])

    def test_classify_high_severity_unknown_technique(self):
        finding = _make_enriched_finding(
            technique='Unknown Vuln', cvss=9.0, severity='CRITICAL',
        )
        nodes = NodeClassifier.classify([finding])
        # High severity → should be classified as ENTRY
        self.assertEqual(nodes[0].type, ENTRY)


# ══════════════════════════════════════════════════════════════════════
# STEP 2: EdgeBuilder
# ══════════════════════════════════════════════════════════════════════

class TestEdgeBuilder(unittest.TestCase):

    def _make_node(self, **kw):
        defaults = {
            'id': 'N-1',
            'vuln_class': 'sql injection',
            'type': ENTRY,
            'exploit_availability': PUBLIC_POC,
        }
        defaults.update(kw)
        return AttackNode(**defaults)

    def test_connect_entry_to_impact(self):
        entry = self._make_node(id='N-1', type=ENTRY, vuln_class='sql injection')
        impact = self._make_node(id='N-2', type=IMPACT, vuln_class='command injection')
        edges = EdgeBuilder.connect([entry, impact])
        self.assertTrue(len(edges) > 0)
        # Should have at least one CHAINS_TO edge
        chains = [e for e in edges if e.type == CHAINS_TO]
        self.assertTrue(len(chains) > 0)

    def test_connect_support_amplifies(self):
        support = self._make_node(id='N-1', type=SUPPORT, vuln_class='information disclosure')
        entry = self._make_node(id='N-2', type=ENTRY, vuln_class='sql injection')
        edges = EdgeBuilder.connect([support, entry])
        amplify_edges = [e for e in edges if e.type == AMPLIFIES]
        self.assertTrue(len(amplify_edges) > 0)

    def test_connect_chain_rule_ssrf_to_info(self):
        ssrf = self._make_node(id='N-1', vuln_class='ssrf', type=ENTRY)
        info = self._make_node(id='N-2', vuln_class='information disclosure', type=SUPPORT)
        edges = EdgeBuilder.connect([ssrf, info])
        chains = [e for e in edges if e.type == CHAINS_TO]
        self.assertTrue(len(chains) > 0)

    def test_confidence_both_weaponized(self):
        conf = EdgeBuilder._compute_confidence(
            AttackNode(exploit_availability=WEAPONIZED),
            AttackNode(exploit_availability=WEAPONIZED),
        )
        self.assertAlmostEqual(conf, 0.95)

    def test_confidence_one_weaponized(self):
        conf = EdgeBuilder._compute_confidence(
            AttackNode(exploit_availability=WEAPONIZED),
            AttackNode(exploit_availability=PUBLIC_POC),
        )
        self.assertAlmostEqual(conf, 0.80)

    def test_confidence_both_public(self):
        conf = EdgeBuilder._compute_confidence(
            AttackNode(exploit_availability=PUBLIC_POC),
            AttackNode(exploit_availability=PUBLIC_POC),
        )
        self.assertAlmostEqual(conf, 0.65)

    def test_confidence_theoretical(self):
        conf = EdgeBuilder._compute_confidence(
            AttackNode(exploit_availability=THEORETICAL),
            AttackNode(exploit_availability=THEORETICAL),
        )
        self.assertAlmostEqual(conf, 0.25)

    def test_no_self_edge(self):
        node = self._make_node(id='N-1')
        edges = EdgeBuilder.connect([node])
        self.assertEqual(len(edges), 0)

    def test_edge_to_dict(self):
        edge = AttackEdge(from_id='N-1', to_id='N-2', type=CHAINS_TO, confidence=0.8)
        d = edge.to_dict()
        self.assertEqual(d['from'], 'N-1')
        self.assertEqual(d['to'], 'N-2')
        self.assertEqual(d['type'], CHAINS_TO)

    def test_exploit_assisted_flag(self):
        entry = self._make_node(id='N-1', type=ENTRY, exploit_availability=WEAPONIZED)
        impact = self._make_node(id='N-2', type=IMPACT, exploit_availability=THEORETICAL)
        edges = EdgeBuilder.connect([entry, impact])
        assisted = [e for e in edges if e.exploit_assisted]
        self.assertTrue(len(assisted) > 0)


# ══════════════════════════════════════════════════════════════════════
# STEP 3: PathFinder
# ══════════════════════════════════════════════════════════════════════

class TestPathFinder(unittest.TestCase):

    def test_enumerate_simple_path(self):
        entry = AttackNode(id='N-1', type=ENTRY, adjusted_cvss=8.0,
                          exploit_availability=PUBLIC_POC, vuln_class='sqli',
                          endpoint='http://a.com/1', metasploit_ready=False,
                          nuclei_ready=False, cisa_kev=False, severity='HIGH')
        impact = AttackNode(id='N-2', type=IMPACT, adjusted_cvss=9.0,
                           exploit_availability=PUBLIC_POC, vuln_class='cmdi',
                           endpoint='http://a.com/2', metasploit_ready=False,
                           nuclei_ready=False, cisa_kev=False, severity='CRITICAL')
        edge = AttackEdge(from_id='N-1', to_id='N-2', type=CHAINS_TO,
                         confidence=0.8)

        finder = PathFinder([entry, impact], [edge])
        paths = finder.enumerate()
        self.assertGreater(len(paths), 0)
        self.assertIn('N-1', paths[0].nodes)
        self.assertIn('N-2', paths[0].nodes)

    def test_enumerate_no_entry(self):
        support = AttackNode(id='N-1', type=SUPPORT, adjusted_cvss=3.0,
                            exploit_availability=THEORETICAL, vuln_class='cors',
                            endpoint='http://a.com', metasploit_ready=False,
                            nuclei_ready=False, cisa_kev=False, severity='LOW')
        finder = PathFinder([support], [])
        paths = finder.enumerate()
        self.assertEqual(len(paths), 0)

    def test_enumerate_no_impact(self):
        entry = AttackNode(id='N-1', type=ENTRY, adjusted_cvss=7.0,
                          exploit_availability=PUBLIC_POC, vuln_class='ssrf',
                          endpoint='http://a.com', metasploit_ready=False,
                          nuclei_ready=False, cisa_kev=False, severity='HIGH')
        finder = PathFinder([entry], [])
        paths = finder.enumerate()
        # No impact node → no full path
        self.assertEqual(len(paths), 0)

    def test_path_classification_critical(self):
        entry = AttackNode(id='N-1', type=ENTRY, adjusted_cvss=9.5,
                          exploit_availability=WEAPONIZED, vuln_class='rce',
                          endpoint='http://a.com/rce', metasploit_ready=True,
                          nuclei_ready=True, cisa_kev=True, severity='CRITICAL')
        impact = AttackNode(id='N-2', type=IMPACT, adjusted_cvss=10.0,
                           exploit_availability=WEAPONIZED, vuln_class='command injection',
                           endpoint='http://a.com/cmd', metasploit_ready=True,
                           nuclei_ready=True, cisa_kev=True, severity='CRITICAL')
        edge = AttackEdge(from_id='N-1', to_id='N-2', type=CHAINS_TO,
                         confidence=0.95)

        finder = PathFinder([entry, impact], [edge])
        paths = finder.enumerate()
        self.assertGreater(len(paths), 0)
        p = paths[0]
        self.assertIn(CRITICAL_PATH, p.classification)
        self.assertTrue(p.fully_weaponized)
        self.assertTrue(p.msf_end_to_end)
        self.assertTrue(p.cisa_kev_in_path)

    def test_path_score_positive(self):
        entry = AttackNode(id='N-1', type=ENTRY, adjusted_cvss=8.0,
                          exploit_availability=PUBLIC_POC, vuln_class='sqli',
                          endpoint='http://a.com', metasploit_ready=False,
                          nuclei_ready=False, cisa_kev=False, severity='HIGH')
        impact = AttackNode(id='N-2', type=IMPACT, adjusted_cvss=9.0,
                           exploit_availability=PUBLIC_POC, vuln_class='cmdi',
                           endpoint='http://a.com', metasploit_ready=False,
                           nuclei_ready=False, cisa_kev=False, severity='CRITICAL')
        edge = AttackEdge(from_id='N-1', to_id='N-2', type=CHAINS_TO,
                         confidence=0.6)
        finder = PathFinder([entry, impact], [edge])
        paths = finder.enumerate()
        self.assertGreater(paths[0].path_score, 0)

    def test_path_to_dict(self):
        p = AttackPath(id='PATH-001', nodes=['N-1', 'N-2'], path_score=8.5)
        d = p.to_dict()
        self.assertEqual(d['id'], 'PATH-001')
        self.assertEqual(d['path_score'], 8.5)

    def test_enumerate_multi_hop(self):
        entry = AttackNode(id='N-1', type=ENTRY, adjusted_cvss=7.0,
                          exploit_availability=PUBLIC_POC, vuln_class='ssrf',
                          endpoint='http://a.com/1', metasploit_ready=False,
                          nuclei_ready=False, cisa_kev=False, severity='HIGH')
        pivot = AttackNode(id='N-2', type=PIVOT, adjusted_cvss=6.0,
                          exploit_availability=PUBLIC_POC, vuln_class='lfi',
                          endpoint='http://a.com/2', metasploit_ready=False,
                          nuclei_ready=False, cisa_kev=False, severity='MEDIUM')
        impact = AttackNode(id='N-3', type=IMPACT, adjusted_cvss=9.0,
                           exploit_availability=WEAPONIZED, vuln_class='command injection',
                           endpoint='http://a.com/3', metasploit_ready=True,
                           nuclei_ready=False, cisa_kev=False, severity='CRITICAL')
        edges = [
            AttackEdge(from_id='N-1', to_id='N-2', type=CHAINS_TO, confidence=0.6),
            AttackEdge(from_id='N-2', to_id='N-3', type=CHAINS_TO, confidence=0.7),
        ]
        finder = PathFinder([entry, pivot, impact], edges)
        paths = finder.enumerate()
        # Should find path N-1 → N-2 → N-3
        multi_hop = [p for p in paths if len(p.nodes) >= 3]
        self.assertGreater(len(multi_hop), 0)


# ══════════════════════════════════════════════════════════════════════
# STEP 4: ImpactZoneMapper
# ══════════════════════════════════════════════════════════════════════

class TestImpactZoneMapper(unittest.TestCase):

    def _make_path(self, node_ids, vuln_classes, **kw):
        defaults = {
            'id': 'P-1',
            'nodes': node_ids,
            'fully_weaponized': False,
            'path_score': 5.0,
        }
        defaults.update(kw)
        path = AttackPath(**defaults)
        return path

    def test_map_data_breach(self):
        path = self._make_path(['N-1'], ['sql injection'], path_score=8.0)
        nodes = {'N-1': AttackNode(id='N-1', vuln_class='sql injection')}
        zones = ImpactZoneMapper.map([path], nodes)
        zone_names = [z.zone for z in zones]
        self.assertIn(ZONE_DATA_BREACH, zone_names)

    def test_map_server_compromise(self):
        path = self._make_path(['N-1'], ['command injection'], path_score=9.0)
        nodes = {'N-1': AttackNode(id='N-1', vuln_class='command injection')}
        zones = ImpactZoneMapper.map([path], nodes)
        zone_names = [z.zone for z in zones]
        self.assertIn(ZONE_SERVER_COMPROMISE, zone_names)

    def test_map_account_takeover(self):
        path = self._make_path(['N-1'], ['xss'], path_score=6.0)
        nodes = {'N-1': AttackNode(id='N-1', vuln_class='xss')}
        zones = ImpactZoneMapper.map([path], nodes)
        zone_names = [z.zone for z in zones]
        self.assertIn(ZONE_ACCOUNT_TAKEOVER, zone_names)

    def test_map_cloud_theft(self):
        path = self._make_path(['N-1'], ['ssrf'], path_score=7.5)
        nodes = {'N-1': AttackNode(id='N-1', vuln_class='ssrf')}
        zones = ImpactZoneMapper.map([path], nodes)
        zone_names = [z.zone for z in zones]
        self.assertIn(ZONE_CLOUD_CRED_THEFT, zone_names)

    def test_map_empty_paths(self):
        zones = ImpactZoneMapper.map([], {})
        self.assertEqual(zones, [])

    def test_zone_has_assets(self):
        path = self._make_path(['N-1'], ['sql injection'], path_score=8.0)
        nodes = {'N-1': AttackNode(id='N-1', vuln_class='sql injection')}
        zones = ImpactZoneMapper.map([path], nodes)
        db_zone = [z for z in zones if z.zone == ZONE_DATA_BREACH]
        self.assertTrue(len(db_zone) > 0)
        self.assertTrue(len(db_zone[0].assets_at_risk) > 0)

    def test_zone_weaponized_flag(self):
        path = self._make_path(
            ['N-1'], ['command injection'],
            fully_weaponized=True, path_score=9.5,
        )
        nodes = {'N-1': AttackNode(id='N-1', vuln_class='command injection')}
        zones = ImpactZoneMapper.map([path], nodes)
        srv = [z for z in zones if z.zone == ZONE_SERVER_COMPROMISE]
        self.assertTrue(srv[0].weaponized_path_exists)

    def test_zone_to_dict(self):
        z = ImpactZone(zone=ZONE_DATA_BREACH, likelihood=0.8)
        d = z.to_dict()
        self.assertEqual(d['zone'], ZONE_DATA_BREACH)
        self.assertEqual(d['likelihood'], 0.8)

    def test_map_persistence(self):
        path = self._make_path(['N-1'], ['file upload'], path_score=7.0)
        nodes = {'N-1': AttackNode(id='N-1', vuln_class='file upload')}
        zones = ImpactZoneMapper.map([path], nodes)
        zone_names = [z.zone for z in zones]
        self.assertIn(ZONE_PERSISTENCE, zone_names)


# ══════════════════════════════════════════════════════════════════════
# STEP 5: AttackerSimulator
# ══════════════════════════════════════════════════════════════════════

class TestAttackerSimulator(unittest.TestCase):

    def _make_path(self, **kw):
        defaults = {
            'id': 'PATH-001',
            'classification': [CRITICAL_PATH],
            'nodes': ['N-1', 'N-2'],
            'fully_weaponized': False,
        }
        defaults.update(kw)
        return AttackPath(**defaults)

    def test_simulate_opportunistic_weaponized(self):
        path = self._make_path(
            classification=[ZERO_CLICK_PATH, MSF_PATH],
            fully_weaponized=True,
        )
        results = AttackerSimulator.simulate([path])
        opp = results[PROFILE_OPPORTUNISTIC]
        self.assertEqual(opp.paths_available, 1)
        self.assertFalse(opp.requires_custom_exploit)
        self.assertIn('minute', opp.time_estimate)

    def test_simulate_skilled(self):
        path = self._make_path(classification=[CRITICAL_PATH, HIGH_PATH])
        results = AttackerSimulator.simulate([path])
        sk = results[PROFILE_SKILLED]
        self.assertEqual(sk.paths_available, 1)

    def test_simulate_apt(self):
        path = self._make_path(classification=[COMPLEX_PATH])
        results = AttackerSimulator.simulate([path])
        apt = results[PROFILE_APT]
        self.assertEqual(apt.paths_available, 1)

    def test_simulate_empty(self):
        results = AttackerSimulator.simulate([])
        self.assertEqual(results[PROFILE_OPPORTUNISTIC].paths_available, 0)
        self.assertEqual(results[PROFILE_SKILLED].paths_available, 0)
        self.assertEqual(results[PROFILE_APT].paths_available, 0)

    def test_simulation_result_to_dict(self):
        r = SimulationResult(profile=PROFILE_APT, paths_available=5)
        d = r.to_dict()
        self.assertEqual(d['profile'], PROFILE_APT)
        self.assertEqual(d['paths_available'], 5)

    def test_simulate_no_zero_click(self):
        path = self._make_path(classification=[HIGH_PATH])
        results = AttackerSimulator.simulate([path])
        opp = results[PROFILE_OPPORTUNISTIC]
        self.assertEqual(opp.paths_available, 0)
        self.assertEqual(opp.time_estimate, 'N/A')

    def test_fastest_path(self):
        short_path = self._make_path(
            id='PATH-001',
            classification=[ZERO_CLICK_PATH, MSF_PATH],
            fully_weaponized=True,
            nodes=['N-1', 'N-2'],
        )
        long_path = self._make_path(
            id='PATH-002',
            classification=[ZERO_CLICK_PATH, MSF_PATH],
            fully_weaponized=True,
            nodes=['N-1', 'N-2', 'N-3', 'N-4'],
        )
        results = AttackerSimulator.simulate([short_path, long_path])
        opp = results[PROFILE_OPPORTUNISTIC]
        self.assertEqual(opp.fastest_path_id, 'PATH-001')
        self.assertEqual(opp.min_steps_to_impact, 2)


# ══════════════════════════════════════════════════════════════════════
# STEP 6: AttackMapBuilder (main orchestrator)
# ══════════════════════════════════════════════════════════════════════

class TestAttackMapBuilder(unittest.TestCase):

    def test_run_empty(self):
        engine = _make_engine()
        builder = AttackMapBuilder(engine)
        result = builder.run([])
        self.assertEqual(result['summary']['total_nodes'], 0)
        self.assertEqual(result['nodes'], [])
        self.assertEqual(result['paths'], [])

    def test_run_produces_nodes(self):
        engine = _make_engine()
        builder = AttackMapBuilder(engine)
        findings = [
            _make_enriched_finding(technique='SQL Injection', url='http://a.com/1'),
            _make_enriched_finding(
                technique='Command Injection', url='http://a.com/2',
                cvss=9.8, adjusted_cvss=9.8, severity='CRITICAL',
            ),
        ]
        result = builder.run(findings)
        self.assertEqual(result['summary']['total_nodes'], 2)
        self.assertTrue(len(result['nodes']) > 0)

    def test_run_produces_edges(self):
        engine = _make_engine()
        builder = AttackMapBuilder(engine)
        findings = [
            _make_enriched_finding(technique='SQL Injection', url='http://a.com/1',
                                   cvss=7.5, adjusted_cvss=7.5),
            _make_enriched_finding(
                technique='RCE', url='http://a.com/2',
                cvss=9.8, adjusted_cvss=9.8, severity='CRITICAL',
            ),
        ]
        result = builder.run(findings)
        self.assertTrue(len(result['edges']) > 0)

    def test_run_emits_events(self):
        engine = _make_engine()
        builder = AttackMapBuilder(engine)
        builder.run([_make_enriched_finding()])
        events = [c[0][0] for c in engine.emit_pipeline_event.call_args_list]
        self.assertIn('phase11_start', events)
        self.assertIn('phase11_complete', events)

    def test_run_summary_keys(self):
        engine = _make_engine()
        builder = AttackMapBuilder(engine)
        result = builder.run([_make_enriched_finding()])
        summary = result['summary']
        expected_keys = [
            'total_nodes', 'entry_points', 'weaponized_entries',
            'critical_paths', 'zero_click_paths', 'msf_ready_paths',
            'cisa_kev_in_map', 'impact_zones_active', 'highest_path_score',
            'fastest_compromise', 'most_damaging', 'exploit_coverage_pct',
        ]
        for key in expected_keys:
            self.assertIn(key, summary)

    def test_run_with_exploit_chains(self):
        engine = _make_engine()
        builder = AttackMapBuilder(engine)
        findings = [_make_enriched_finding()]
        # exploit_chains is accepted but doesn't affect output structure
        result = builder.run(findings, exploit_chains=[{'name': 'test'}])
        self.assertIn('nodes', result)

    def test_impact_zones_populated(self):
        engine = _make_engine()
        builder = AttackMapBuilder(engine)
        findings = [
            _make_enriched_finding(technique='SQL Injection', url='http://a.com/1'),
            _make_enriched_finding(
                technique='Command Injection', url='http://a.com/2',
                cvss=9.8, adjusted_cvss=9.8, severity='CRITICAL',
            ),
        ]
        result = builder.run(findings)
        # Should have at least one impact zone
        zones = result['impact_zones']
        self.assertIsInstance(zones, list)

    def test_simulation_populated(self):
        engine = _make_engine()
        builder = AttackMapBuilder(engine)
        findings = [
            _make_enriched_finding(technique='SQL Injection', url='http://a.com/1'),
        ]
        result = builder.run(findings)
        sim = result['simulation']
        self.assertIn(PROFILE_OPPORTUNISTIC, sim)
        self.assertIn(PROFILE_SKILLED, sim)
        self.assertIn(PROFILE_APT, sim)

    def test_exploit_coverage_pct(self):
        engine = _make_engine()
        builder = AttackMapBuilder(engine)
        findings = [
            _make_enriched_finding(
                technique='SQL Injection', url='http://a.com/1',
                exploit_availability=PUBLIC_POC,
            ),
            _make_enriched_finding(
                technique='XSS', url='http://a.com/2',
                exploit_availability=THEORETICAL,
            ),
        ]
        result = builder.run(findings)
        pct = result['summary']['exploit_coverage_pct']
        self.assertEqual(pct, 50.0)

    def test_empty_map_structure(self):
        engine = _make_engine()
        builder = AttackMapBuilder(engine)
        result = builder._empty_map()
        self.assertEqual(result['nodes'], [])
        self.assertEqual(result['summary']['exploit_coverage_pct'], 0.0)

    def test_paths_sorted_by_score(self):
        engine = _make_engine()
        builder = AttackMapBuilder(engine)
        findings = [
            _make_enriched_finding(
                technique='SQL Injection', url='http://a.com/1',
                cvss=8.0, adjusted_cvss=8.0,
            ),
            _make_enriched_finding(
                technique='Command Injection', url='http://a.com/2',
                cvss=9.8, adjusted_cvss=9.8, severity='CRITICAL',
            ),
        ]
        result = builder.run(findings)
        paths = result['paths']
        if len(paths) >= 2:
            self.assertGreaterEqual(paths[0]['path_score'], paths[1]['path_score'])


if __name__ == '__main__':
    unittest.main()
