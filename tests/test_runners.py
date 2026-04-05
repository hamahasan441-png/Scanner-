#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for core/runners/ — ReconRunner, ScanRunner, VerifyRunner, ReportRunner."""

import sys
import os
import unittest
from unittest.mock import MagicMock, patch, call

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.runners.recon_runner import ReconResult, ReconRunner
from core.runners.scan_runner import ScanResult, ScanRunner
from core.runners.verify_runner import VerifyResult, VerifyRunner
from core.runners.report_runner import ReportResult, ReportRunner


# ---------------------------------------------------------------------------
# Shared engine factory
# ---------------------------------------------------------------------------

def _make_engine(**overrides):
    engine = MagicMock()
    engine.config = overrides.get('config', {'verbose': False, 'modules': {}})
    engine.config.setdefault('modules', {})
    engine.adaptive = MagicMock()
    engine.adaptive.get_depth_boost.return_value = 0
    engine.adaptive.should_rediscover.return_value = False
    engine.scope = MagicMock()
    engine.scope.filter_urls.side_effect = lambda x: x
    engine.scope.filter_parameters.side_effect = lambda x: x
    engine.scope.is_in_scope.return_value = True
    engine.emit_pipeline_event = MagicMock()
    engine.findings = []
    engine.context = MagicMock()
    engine.prioritizer = MagicMock()
    engine.baseline_engine = MagicMock()
    engine.ai = MagicMock()
    engine.ai.get_attack_strategy.return_value = {}
    engine.learning = MagicMock()
    engine.verifier = MagicMock()
    engine.persistence = MagicMock()
    engine.persistence.is_tested.return_value = False
    engine.persistence.execute_with_retry.side_effect = lambda fn, key: fn()
    engine.requester = MagicMock()
    engine.requester.total_requests = 0
    engine.db = MagicMock()
    engine._modules = {}
    for k, v in overrides.items():
        setattr(engine, k, v)
    return engine


# ===========================================================================
# ReconResult
# ===========================================================================

class TestReconResultDefaults(unittest.TestCase):
    def test_defaults(self):
        r = ReconResult()
        self.assertIsInstance(r.urls, set)
        self.assertEqual(len(r.urls), 0)
        self.assertEqual(r.forms, [])
        self.assertEqual(r.parameters, [])
        self.assertIsNone(r.shield_profile)
        self.assertIsNone(r.real_ip_result)
        self.assertIsNone(r.fanout_result)

    def test_custom_values(self):
        r = ReconResult(urls={'http://a'}, shield_profile={'cdn': {}})
        self.assertIn('http://a', r.urls)
        self.assertIsNotNone(r.shield_profile)


# ===========================================================================
# ReconRunner
# ===========================================================================

class TestReconRunnerInit(unittest.TestCase):
    def test_stores_engine_and_config(self):
        eng = _make_engine()
        runner = ReconRunner(eng)
        self.assertIs(runner.engine, eng)
        self.assertIs(runner.config, eng.config)


class TestReconRunnerRun(unittest.TestCase):
    """Integration-level tests for ReconRunner.run()."""

    @patch('core.runners.recon_runner.ReconRunner._passive_recon')
    @patch('core.runners.recon_runner.ReconRunner._real_ip_discover')
    @patch('core.runners.recon_runner.ReconRunner._shield_detect')
    def test_run_with_fanout(self, mock_shield, mock_rip, mock_passive):
        mock_shield.return_value = {'cdn': {}}
        mock_rip.return_value = {'origin_ip': '1.2.3.4'}
        fanout = MagicMock()
        fanout.urls = {'http://a'}
        fanout.forms = [{'action': '/login'}]
        fanout.params = [('http://a', 'get', 'q', 'x', 'passive')]
        mock_passive.return_value = fanout

        eng = _make_engine()
        result = ReconRunner(eng).run('http://target')

        self.assertEqual(result.urls, {'http://a'})
        self.assertEqual(result.forms, [{'action': '/login'}])
        self.assertEqual(len(result.parameters), 1)
        self.assertIs(result.fanout_result, fanout)

    @patch('core.runners.recon_runner.ReconRunner._legacy_discovery')
    @patch('core.runners.recon_runner.ReconRunner._passive_recon')
    @patch('core.runners.recon_runner.ReconRunner._real_ip_discover')
    @patch('core.runners.recon_runner.ReconRunner._shield_detect')
    def test_run_fallback_to_legacy(self, mock_shield, mock_rip, mock_passive, mock_legacy):
        mock_shield.return_value = None
        mock_rip.return_value = None
        mock_passive.return_value = None
        mock_legacy.return_value = ({'http://b'}, [{'f': 1}], [('p',)])

        eng = _make_engine()
        result = ReconRunner(eng).run('http://target')

        mock_legacy.assert_called_once_with(
            'http://target',
            effective_target='http://target',
            shield_profile=None,
        )
        self.assertEqual(result.urls, {'http://b'})
        self.assertIsNone(result.fanout_result)


class TestShieldDetect(unittest.TestCase):

    @patch('core.shield_detector.ShieldDetector')
    def test_enabled_success(self, MockSD):
        profile = {'cdn': {'detected': True, 'provider': 'CF'},
                   'waf': {'detected': False, 'provider': None}}
        MockSD.return_value.run.return_value = profile

        eng = _make_engine(config={'verbose': False, 'modules': {'shield_detect': True}})
        result = ReconRunner(eng)._shield_detect('http://t', MagicMock())

        self.assertEqual(result, profile)
        eng.emit_pipeline_event.assert_called_once()
        args = eng.emit_pipeline_event.call_args
        self.assertEqual(args[0][0], 'shield_detection')

    def test_disabled_returns_none(self):
        eng = _make_engine(config={'verbose': False, 'modules': {'shield_detect': False}})
        self.assertIsNone(ReconRunner(eng)._shield_detect('http://t', None))

    def test_disabled_default(self):
        eng = _make_engine(config={'verbose': False, 'modules': {}})
        self.assertIsNone(ReconRunner(eng)._shield_detect('http://t', None))

    @patch('core.shield_detector.ShieldDetector', side_effect=RuntimeError('boom'))
    def test_exception_verbose(self, _):
        eng = _make_engine(config={'verbose': True, 'modules': {'shield_detect': True}})
        result = ReconRunner(eng)._shield_detect('http://t', None)
        self.assertIsNone(result)

    @patch('core.shield_detector.ShieldDetector', side_effect=RuntimeError('boom'))
    def test_exception_silent(self, _):
        eng = _make_engine(config={'verbose': False, 'modules': {'shield_detect': True}})
        result = ReconRunner(eng)._shield_detect('http://t', None)
        self.assertIsNone(result)


class TestRealIPDiscover(unittest.TestCase):

    @patch('core.real_ip_scanner.RealIPScanner')
    def test_enabled_needs_discovery(self, MockScanner):
        ip_result = {'origin_ip': '5.6.7.8', 'confidence': 0.9,
                     'method': 'dns', 'all_candidates': ['5.6.7.8']}
        MockScanner.return_value.run.return_value = ip_result

        eng = _make_engine(config={'verbose': False, 'modules': {'real_ip': True}})
        shield = {'needs_origin_discovery': True}
        result = ReconRunner(eng)._real_ip_discover('http://t', shield)

        self.assertEqual(result, ip_result)
        eng.emit_pipeline_event.assert_called_once_with('real_ip_discovery', {
            'origin_ip': '5.6.7.8', 'confidence': 0.9,
            'method': 'dns', 'candidates': 1,
        })

    def test_disabled(self):
        eng = _make_engine(config={'verbose': False, 'modules': {'real_ip': False}})
        self.assertIsNone(ReconRunner(eng)._real_ip_discover('http://t', None))

    def test_shield_says_no_discovery(self):
        eng = _make_engine(config={'verbose': False, 'modules': {'real_ip': True}})
        shield = {'needs_origin_discovery': False}
        self.assertIsNone(ReconRunner(eng)._real_ip_discover('http://t', shield))

    @patch('core.real_ip_scanner.RealIPScanner')
    def test_no_shield_profile_defaults_needs_true(self, MockScanner):
        MockScanner.return_value.run.return_value = {'origin_ip': '1.1.1.1',
                                                      'confidence': 0.5,
                                                      'method': 'brute',
                                                      'all_candidates': []}
        eng = _make_engine(config={'verbose': False, 'modules': {'real_ip': True}})
        result = ReconRunner(eng)._real_ip_discover('http://t', None)
        self.assertIsNotNone(result)

    @patch('core.real_ip_scanner.RealIPScanner', side_effect=RuntimeError('fail'))
    def test_exception_returns_none(self, _):
        eng = _make_engine(config={'verbose': True, 'modules': {'real_ip': True}})
        self.assertIsNone(ReconRunner(eng)._real_ip_discover('http://t', None))


class TestPassiveRecon(unittest.TestCase):

    @patch('core.passive_recon.PassiveReconFanout')
    def test_enabled_success(self, MockFanout):
        fanout_result = MagicMock()
        fanout_result.to_dict.return_value = {'urls': 5}
        MockFanout.return_value.run.return_value = fanout_result

        eng = _make_engine(config={'verbose': False, 'modules': {'passive_recon': True}})
        result = ReconRunner(eng)._passive_recon('http://t')

        self.assertIs(result, fanout_result)
        eng.emit_pipeline_event.assert_called_once()

    def test_disabled(self):
        eng = _make_engine(config={'verbose': False, 'modules': {}})
        self.assertIsNone(ReconRunner(eng)._passive_recon('http://t'))

    @patch('core.passive_recon.PassiveReconFanout', side_effect=RuntimeError('x'))
    def test_exception(self, _):
        eng = _make_engine(config={'verbose': True, 'modules': {'passive_recon': True}})
        self.assertIsNone(ReconRunner(eng)._passive_recon('http://t'))


class TestLegacyDiscovery(unittest.TestCase):

    @patch('modules.discovery.DiscoveryModule')
    @patch('modules.tech_exploits.TechExploitScanner')
    @patch('modules.network_exploits.NetworkExploitScanner')
    @patch('modules.port_scanner.PortScanner')
    @patch('modules.reconnaissance.ReconModule')
    @patch('utils.crawler.Crawler')
    def test_all_modules_enabled(self, MockCrawler, MockRecon, MockPort,
                                  MockNetExploit, MockTech, MockDisc):
        MockCrawler.return_value.crawl.return_value = ({'http://a'}, [], [])
        MockCrawler.return_value.endpoint_graph = None
        MockPort.return_value.run.return_value = [{'port': 80}]
        MockDisc.return_value.endpoints = []

        eng = _make_engine(config={
            'verbose': False, 'depth': 3,
            'modules': {'recon': True, 'ports': '80,443',
                        'net_exploit': True, 'tech_exploit': True,
                        'discovery': True}})
        urls, forms, params = ReconRunner(eng)._legacy_discovery('http://example.com')

        MockRecon.assert_called_once()
        MockPort.assert_called_once()
        MockNetExploit.assert_called_once()
        MockTech.assert_called_once()
        MockDisc.assert_called_once()
        self.assertIn('http://a', urls)

    @patch('utils.crawler.Crawler')
    def test_all_modules_disabled_just_crawl(self, MockCrawler):
        MockCrawler.return_value.crawl.return_value = ({'http://c'}, [{'form': 1}], [('p',)])
        MockCrawler.return_value.endpoint_graph = None

        eng = _make_engine(config={'verbose': False, 'depth': 2, 'modules': {}})
        urls, forms, params = ReconRunner(eng)._legacy_discovery('http://target')

        self.assertIn('http://c', urls)
        self.assertEqual(forms, [{'form': 1}])
        eng.scope.filter_urls.assert_called_once()
        eng.scope.filter_parameters.assert_called_once()

    @patch('modules.discovery.DiscoveryModule')
    @patch('utils.crawler.Crawler')
    def test_discovery_adds_query_params(self, MockCrawler, MockDisc):
        MockCrawler.return_value.crawl.return_value = (set(), [], [])
        MockCrawler.return_value.endpoint_graph = None
        MockDisc.return_value.endpoints = ['http://t/page?id=1&name=foo']

        eng = _make_engine(config={
            'verbose': False, 'depth': 2,
            'modules': {'discovery': True}})
        urls, forms, params = ReconRunner(eng)._legacy_discovery('http://t')

        self.assertIn('http://t/page?id=1&name=foo', urls)
        eng.adaptive.add_new_endpoint.assert_called_once()
        param_names = [p[2] for p in params]
        self.assertIn('id', param_names)
        self.assertIn('name', param_names)

    @patch('utils.crawler.Crawler')
    def test_scope_filtering_applied(self, MockCrawler):
        MockCrawler.return_value.crawl.return_value = ({'http://a', 'http://b'}, [], [('p',)])
        MockCrawler.return_value.endpoint_graph = None
        eng = _make_engine(config={'verbose': False, 'depth': 1, 'modules': {}})
        eng.scope.filter_urls.side_effect = lambda x: {u for u in x if u == 'http://a'}

        urls, _, _ = ReconRunner(eng)._legacy_discovery('http://t')
        self.assertEqual(urls, {'http://a'})

    @patch('utils.crawler.Crawler')
    def test_depth_boost_applied(self, MockCrawler):
        MockCrawler.return_value.crawl.return_value = (set(), [], [])
        MockCrawler.return_value.endpoint_graph = None

        eng = _make_engine(config={'verbose': False, 'depth': 2, 'modules': {}})
        eng.adaptive.get_depth_boost.return_value = 2
        ReconRunner(eng)._legacy_discovery('http://t')

        crawl_call = MockCrawler.return_value.crawl.call_args
        self.assertEqual(crawl_call[0][1], 4)

    @patch('utils.crawler.Crawler')
    @patch('modules.reconnaissance.ReconModule', side_effect=RuntimeError('err'))
    def test_recon_module_exception(self, _, MockCrawler):
        MockCrawler.return_value.crawl.return_value = (set(), [], [])
        MockCrawler.return_value.endpoint_graph = None

        eng = _make_engine(config={'verbose': True, 'depth': 1,
                                   'modules': {'recon': True}})
        # Should not raise
        ReconRunner(eng)._legacy_discovery('http://t')

    @patch('utils.crawler.Crawler')
    def test_verbose_graph_summary(self, MockCrawler):
        MockCrawler.return_value.crawl.return_value = (set(), [], [])
        MockCrawler.return_value.endpoint_graph = {'a': 'b'}
        MockCrawler.return_value.get_graph_summary.return_value = 'graph info'

        eng = _make_engine(config={'verbose': True, 'depth': 1, 'modules': {}})
        ReconRunner(eng)._legacy_discovery('http://t')
        MockCrawler.return_value.get_graph_summary.assert_called_once()


# ===========================================================================
# ScanResult
# ===========================================================================

class TestScanResultDefaults(unittest.TestCase):
    def test_defaults(self):
        s = ScanResult()
        self.assertEqual(s.enriched_params, [])
        self.assertEqual(s.prioritized_urls, [])
        self.assertIsNone(s.intel_bundle)
        self.assertIsNone(s.scan_queue)
        self.assertIsNone(s.ai_strategy)


# ===========================================================================
# ScanRunner
# ===========================================================================

class TestScanRunnerRun(unittest.TestCase):

    def _make_recon(self):
        recon = MagicMock()
        recon.parameters = [('http://a', 'get', 'q', '1', 'crawl')]
        recon.urls = {'http://a'}
        recon.real_ip_result = None
        recon.shield_profile = None
        recon.fanout_result = None
        return recon

    @patch('core.runners.scan_runner.ScanRunner._run_scan_workers')
    @patch('core.runners.scan_runner.ScanRunner._run_modules')
    @patch('core.runners.scan_runner.ScanRunner._build_baselines')
    @patch('core.runners.scan_runner.ScanRunner._build_scan_queue')
    @patch('core.runners.scan_runner.ScanRunner._intelligence_enrichment')
    def test_full_flow(self, mock_intel, mock_queue, mock_base, mock_mods, mock_workers):
        mock_intel.return_value = None
        mock_queue.return_value = None

        eng = _make_engine()
        eng.context.analyze_parameters.return_value = [{'url': 'http://a', 'param': 'q',
                                                         'method': 'get', 'value': '1'}]
        eng.prioritizer.prioritize_parameters.return_value = [{'url': 'http://a'}]
        eng.prioritizer.prioritize_urls.return_value = [('http://a', 10)]
        recon = self._make_recon()

        result = ScanRunner(eng).run('http://a', recon)

        eng.context.analyze_parameters.assert_called_once()
        eng.prioritizer.prioritize_parameters.assert_called_once()
        eng.persistence.save_progress.assert_called_once()
        eng._enrich_finding_signals.assert_called_once()
        # scan_queue is None so workers not called
        mock_workers.assert_not_called()

    @patch('core.runners.scan_runner.ScanRunner._run_scan_workers')
    @patch('core.runners.scan_runner.ScanRunner._run_modules')
    @patch('core.runners.scan_runner.ScanRunner._build_baselines')
    @patch('core.runners.scan_runner.ScanRunner._build_scan_queue')
    @patch('core.runners.scan_runner.ScanRunner._intelligence_enrichment')
    def test_workers_run_when_queue_present(self, mock_intel, mock_queue,
                                             mock_base, mock_mods, mock_workers):
        mock_intel.return_value = MagicMock()
        mock_queue.return_value = ['task1']

        eng = _make_engine()
        eng.context.analyze_parameters.return_value = []
        eng.prioritizer.prioritize_parameters.return_value = []
        eng.prioritizer.prioritize_urls.return_value = []

        result = ScanRunner(eng).run('http://a', self._make_recon())
        mock_workers.assert_called_once_with(['task1'])

    @patch('core.runners.scan_runner.ScanRunner._run_scan_workers')
    @patch('core.runners.scan_runner.ScanRunner._run_modules')
    @patch('core.runners.scan_runner.ScanRunner._build_baselines')
    @patch('core.runners.scan_runner.ScanRunner._build_scan_queue')
    @patch('core.runners.scan_runner.ScanRunner._intelligence_enrichment')
    def test_verbose_ai_strategy(self, mock_intel, mock_queue, mock_base,
                                  mock_mods, mock_workers):
        mock_intel.return_value = None
        mock_queue.return_value = None

        eng = _make_engine(config={'verbose': True, 'modules': {}})
        eng.ai.get_attack_strategy.return_value = {'module_order': ['sqli', 'xss']}
        eng.context.analyze_parameters.return_value = []
        eng.prioritizer.prioritize_parameters.return_value = []
        eng.prioritizer.prioritize_urls.return_value = []

        result = ScanRunner(eng).run('http://a', self._make_recon())
        self.assertEqual(result.ai_strategy, {'module_order': ['sqli', 'xss']})


class TestIntelligenceEnrichment(unittest.TestCase):

    @patch('core.intelligence_enricher.IntelligenceEnricher')
    def test_enabled(self, MockIE):
        bundle = MagicMock()
        bundle.to_dict.return_value = {'tech': 'php'}
        MockIE.return_value.run.return_value = bundle

        eng = _make_engine(config={'verbose': False, 'modules': {'enrich': True}})
        result = ScanRunner(eng)._intelligence_enrichment(MagicMock(), [], set())

        self.assertIs(result, bundle)
        eng.emit_pipeline_event.assert_called_once_with('phase6_result', {'tech': 'php'})

    def test_disabled(self):
        eng = _make_engine(config={'verbose': False, 'modules': {}})
        self.assertIsNone(ScanRunner(eng)._intelligence_enrichment(None, [], set()))

    @patch('core.intelligence_enricher.IntelligenceEnricher', side_effect=RuntimeError('x'))
    def test_exception(self, _):
        eng = _make_engine(config={'verbose': True, 'modules': {'enrich': True}})
        self.assertIsNone(ScanRunner(eng)._intelligence_enrichment(None, [], set()))

    @patch('core.intelligence_enricher.IntelligenceEnricher')
    def test_no_init_resp(self, MockIE):
        bundle = MagicMock()
        bundle.to_dict.return_value = {}
        MockIE.return_value.run.return_value = bundle

        eng = _make_engine(config={'verbose': False, 'modules': {'enrich': True}})
        ScanRunner(eng)._intelligence_enrichment(None, [], set())

        call_kwargs = MockIE.return_value.run.call_args
        self.assertEqual(call_kwargs[1]['responses'], [])


class TestBuildScanQueue(unittest.TestCase):

    @patch('core.scan_priority_queue.ScanPriorityQueue')
    def test_with_all_data(self, MockPQ):
        queue_data = [1, 2, 3]
        MockPQ.return_value.build.return_value = queue_data

        eng = _make_engine(config={'verbose': False, 'modules': {'enrich': True}})
        intel = MagicMock()
        shield = {'waf': {'type': 'modsec'}}
        real_ip = {'origin_ip': '1.2.3.4'}
        fanout = MagicMock()
        fanout._asset_graph = 'graph'

        result = ScanRunner(eng)._build_scan_queue([], set(), intel, real_ip, shield, fanout)

        self.assertEqual(result, queue_data)
        eng.emit_pipeline_event.assert_called_once_with('phase7_result', {'queue_size': 3})

    def test_none_intel_bundle(self):
        eng = _make_engine(config={'verbose': False, 'modules': {'enrich': True}})
        result = ScanRunner(eng)._build_scan_queue([], set(), None, None, None, None)
        self.assertIsNone(result)

    def test_enrich_disabled(self):
        eng = _make_engine(config={'verbose': False, 'modules': {}})
        result = ScanRunner(eng)._build_scan_queue([], set(), MagicMock(), None, None, None)
        self.assertIsNone(result)

    @patch('core.scan_priority_queue.ScanPriorityQueue', side_effect=RuntimeError('err'))
    def test_exception(self, _):
        eng = _make_engine(config={'verbose': True, 'modules': {'enrich': True}})
        result = ScanRunner(eng)._build_scan_queue([], set(), MagicMock(), None, None, None)
        self.assertIsNone(result)


class TestBuildBaselines(unittest.TestCase):

    def test_deduplication(self):
        eng = _make_engine()
        params = [
            {'method': 'get', 'url': 'http://a', 'param': 'q', 'value': '1'},
            {'method': 'get', 'url': 'http://a', 'param': 'q', 'value': '2'},
            {'method': 'post', 'url': 'http://a', 'param': 'q', 'value': '3'},
        ]
        ScanRunner(eng)._build_baselines(params)
        # get:http://a:q appears twice, second is deduped; post:http://a:q is unique
        self.assertEqual(eng.baseline_engine.get_baseline.call_count, 2)

    def test_empty_params(self):
        eng = _make_engine()
        ScanRunner(eng)._build_baselines([])
        eng.baseline_engine.get_baseline.assert_not_called()


class TestRunModules(unittest.TestCase):

    def _ep(self, url='http://a', method='get', param='q', value='1'):
        return {'url': url, 'method': method, 'param': param, 'value': value}

    def test_ai_strategy_ordering(self):
        mod_xss = MagicMock(name='xss_mod', requires_reflection=False)
        mod_xss.name = 'XSS'
        mod_sqli = MagicMock(name='sqli_mod', requires_reflection=False)
        mod_sqli.name = 'SQLi'
        eng = _make_engine()
        eng._modules = {'sqli': mod_sqli, 'xss': mod_xss}
        eng.baseline_engine.reflection_check.return_value = True
        eng.adaptive.get_delay.return_value = 0

        strategy = {'module_order': ['xss', 'sqli']}
        ScanRunner(eng)._run_modules([self._ep()], [], strategy)

        # Both modules should have been tested
        self.assertTrue(mod_xss.test.called or eng.persistence.execute_with_retry.called)

    def test_no_ai_strategy_fallback(self):
        mod = MagicMock(requires_reflection=False)
        mod.name = 'test_mod'
        eng = _make_engine()
        eng._modules = {'test': mod}
        eng.baseline_engine.reflection_check.return_value = True
        eng.adaptive.get_delay.return_value = 0

        ScanRunner(eng)._run_modules([self._ep()], [], None)
        eng.persistence.execute_with_retry.assert_called()

    def test_reflection_gate_skipping(self):
        mod = MagicMock(requires_reflection=True)
        mod.name = 'XSS'
        eng = _make_engine()
        eng._modules = {'xss': mod}
        eng.baseline_engine.reflection_check.return_value = False

        ScanRunner(eng)._run_modules([self._ep()], [], None)
        eng.persistence.mark_tested.assert_called()

    def test_reflection_fallback_for_known_modules(self):
        """xss/ssti in _FALLBACK_REFLECTION_MODULES are skipped when no reflection."""
        mod = MagicMock(spec=[])  # no requires_reflection attr
        mod.name = 'SSTI'
        eng = _make_engine()
        eng._modules = {'ssti': mod}
        eng.baseline_engine.reflection_check.return_value = False

        ScanRunner(eng)._run_modules([self._ep()], [], None)
        eng.persistence.mark_tested.assert_called()

    def test_persistence_skip_already_tested(self):
        mod = MagicMock(requires_reflection=False)
        mod.name = 'test_mod'
        eng = _make_engine()
        eng._modules = {'test': mod}
        eng.persistence.is_tested.return_value = True
        eng.baseline_engine.reflection_check.return_value = True

        ScanRunner(eng)._run_modules([self._ep()], [], None)
        eng.persistence.execute_with_retry.assert_not_called()

    def test_url_testing(self):
        mod = MagicMock(requires_reflection=False)
        mod.name = 'url_mod'
        eng = _make_engine()
        eng._modules = {'url_test': mod}
        eng.persistence.is_tested.return_value = False
        eng.baseline_engine.reflection_check.return_value = True

        ScanRunner(eng)._run_modules([], [('http://x', 10)], None)
        # execute_with_retry called for url test
        eng.persistence.execute_with_retry.assert_called()

    def test_url_skip_already_tested(self):
        mod = MagicMock(requires_reflection=False)
        mod.name = 'url_mod'
        eng = _make_engine()
        eng._modules = {'url_test': mod}
        eng.persistence.is_tested.return_value = True
        eng.baseline_engine.reflection_check.return_value = True

        ScanRunner(eng)._run_modules([], [('http://x', 10)], None)
        eng.persistence.execute_with_retry.assert_not_called()

    def test_module_test_invoked_via_retry(self):
        mod = MagicMock(requires_reflection=False)
        mod.name = 'mod'
        eng = _make_engine()
        eng._modules = {'mod': mod}
        eng.baseline_engine.reflection_check.return_value = True
        eng.adaptive.get_delay.return_value = 0

        ScanRunner(eng)._run_modules([self._ep()], [], None)
        # The test function is called via execute_with_retry's side_effect
        mod.test.assert_called_once_with('http://a', 'get', 'q', '1')


class TestRunScanWorkers(unittest.TestCase):

    @patch('core.scan_worker_pool.ScanWorkerPool')
    def test_success(self, MockPool):
        eng = _make_engine()
        eng.findings = [1, 2]
        ScanRunner(eng)._run_scan_workers(['task'])

        MockPool.return_value.run.assert_called_once_with(['task'])
        eng.emit_pipeline_event.assert_called_once_with('phase8_result',
                                                         {'additional_findings': 2})

    @patch('core.scan_worker_pool.ScanWorkerPool', side_effect=RuntimeError('x'))
    def test_exception(self, _):
        eng = _make_engine(config={'verbose': True, 'modules': {}})
        # Should not raise
        ScanRunner(eng)._run_scan_workers(['task'])


# ===========================================================================
# VerifyResult
# ===========================================================================

class TestVerifyResultDefaults(unittest.TestCase):
    def test_defaults(self):
        v = VerifyResult()
        self.assertIsNone(v.verification_result)
        self.assertEqual(v.exploit_chains, [])


# ===========================================================================
# VerifyRunner
# ===========================================================================

class TestVerifyRunnerRun(unittest.TestCase):

    @patch('core.runners.verify_runner.VerifyRunner._exploit_search')
    @patch('core.runners.verify_runner.VerifyRunner._post_worker_verify')
    @patch('core.runners.verify_runner.VerifyRunner._adaptive_rediscovery')
    def test_full_flow(self, mock_adapt, mock_pwv, mock_exploit):
        finding = MagicMock()
        finding.technique = 'XSS'
        finding.payload = '<script>'
        finding.param = 'q'

        eng = _make_engine()
        eng.findings = [finding]
        eng.verifier.verify_findings.return_value = [finding]
        mock_pwv.return_value = None

        result = VerifyRunner(eng).run('http://t')

        eng.verifier.verify_findings.assert_called_once_with([finding])
        eng.learning.record_success.assert_called_once_with('XSS', '<script>')
        eng.ai.record_finding.assert_called_once_with('XSS', 'q', '<script>')
        eng.learning.update_thresholds.assert_called_once()
        eng.learning.save.assert_called_once()
        eng.ai.save.assert_called_once()
        mock_adapt.assert_called_once_with('http://t')

    @patch('core.runners.verify_runner.VerifyRunner._exploit_search')
    @patch('core.runners.verify_runner.VerifyRunner._post_worker_verify')
    @patch('core.runners.verify_runner.VerifyRunner._adaptive_rediscovery')
    def test_exploit_chains_from_verification(self, mock_adapt, mock_pwv, mock_exploit):
        eng = _make_engine()
        eng.verifier.verify_findings.return_value = []

        vr = MagicMock()
        vr.exploit_chains = ['chain1', 'chain2']
        mock_pwv.return_value = vr

        result = VerifyRunner(eng).run('http://t')
        self.assertEqual(result.exploit_chains, ['chain1', 'chain2'])
        self.assertIs(result.verification_result, vr)


class TestSelfLearning(unittest.TestCase):

    @patch('core.runners.verify_runner.VerifyRunner._exploit_search')
    @patch('core.runners.verify_runner.VerifyRunner._post_worker_verify', return_value=None)
    @patch('core.runners.verify_runner.VerifyRunner._adaptive_rediscovery')
    def test_records_findings(self, *_):
        f1 = MagicMock(technique='SQLi', payload="' OR 1=1", param='id')
        f2 = MagicMock(technique='XSS', payload='<img>', param='name')

        eng = _make_engine()
        eng.findings = [f1, f2]
        eng.verifier.verify_findings.return_value = [f1, f2]

        VerifyRunner(eng).run('http://t')
        self.assertEqual(eng.learning.record_success.call_count, 2)
        self.assertEqual(eng.ai.record_finding.call_count, 2)


class TestAdaptiveRediscovery(unittest.TestCase):

    def test_runs_up_to_max_rounds(self):
        eng = _make_engine(config={'verbose': False, 'modules': {'discovery': True}})
        # should_rediscover is checked at top of while; with MAX_ROUNDS=3 it runs 3 iterations
        eng.adaptive.should_rediscover.return_value = True
        eng.adaptive.new_endpoints = set()
        eng.context.analyze_parameters.return_value = []
        eng.prioritizer.prioritize_parameters.return_value = []

        VerifyRunner(eng)._adaptive_rediscovery('http://t')
        # Called once per iteration for MAX_ROUNDS (3) iterations, plus the exit check
        self.assertGreaterEqual(eng.adaptive.should_rediscover.call_count, 3)

    def test_scope_filtering(self):
        eng = _make_engine(config={'verbose': False, 'modules': {'discovery': True}})
        eng.adaptive.should_rediscover.side_effect = [True, False]
        eng.adaptive.new_endpoints = {'http://in?q=1', 'http://out?q=2'}
        eng.scope.is_in_scope.side_effect = lambda u: 'in' in u
        eng.context.analyze_parameters.return_value = []
        eng.prioritizer.prioritize_parameters.return_value = []

        VerifyRunner(eng)._adaptive_rediscovery('http://t')

        # Only 'http://in?q=1' should have been processed
        scope_calls = eng.scope.is_in_scope.call_args_list
        checked_urls = [c[0][0] for c in scope_calls]
        self.assertIn('http://in?q=1', checked_urls)

    def test_exception_breaks_loop(self):
        eng = _make_engine(config={'verbose': True, 'modules': {'discovery': True}})
        eng.adaptive.should_rediscover.return_value = True
        eng.adaptive.new_endpoints = {'http://a?q=1'}
        eng.scope.is_in_scope.side_effect = RuntimeError('scope error')

        # Should not raise
        VerifyRunner(eng)._adaptive_rediscovery('http://t')
        # Loop broken after first exception
        self.assertEqual(eng.adaptive.should_rediscover.call_count, 1)

    def test_no_run_when_discovery_disabled(self):
        eng = _make_engine(config={'verbose': False, 'modules': {}})
        eng.adaptive.should_rediscover.return_value = True
        VerifyRunner(eng)._adaptive_rediscovery('http://t')
        # should_rediscover returns True, but discovery=False → no loop
        eng.context.analyze_parameters.assert_not_called()

    def test_new_params_scanned_by_modules(self):
        eng = _make_engine(config={'verbose': False, 'modules': {'discovery': True}})
        eng.adaptive.should_rediscover.side_effect = [True, False]
        eng.adaptive.new_endpoints = {'http://a?id=5'}
        mod = MagicMock()
        eng._modules = {'sqli': mod}
        enriched = [{'url': 'http://a', 'method': 'get', 'param': 'id', 'value': '5'}]
        eng.context.analyze_parameters.return_value = enriched
        eng.prioritizer.prioritize_parameters.return_value = enriched

        VerifyRunner(eng)._adaptive_rediscovery('http://t')
        mod.test.assert_called_once()


class TestPostWorkerVerify(unittest.TestCase):

    @patch('core.post_worker_verifier.PostWorkerVerifier')
    def test_enabled_with_findings_and_chains(self, MockPWV):
        chain = MagicMock()
        chain.to_dict.return_value = {'name': 'SQLi→RCE'}
        chain.name = 'SQLi→RCE'
        chain.combined_cvss = 9.8
        chain.combined_severity = 'CRITICAL'
        chain.steps = ['SQLi', 'RCE']

        vr = MagicMock()
        vr.verified_findings = ['f1']
        vr.exploit_chains = [chain]
        MockPWV.return_value.run.return_value = vr

        finding = MagicMock()
        eng = _make_engine(config={'verbose': False, 'modules': {'chain_detect': True}})
        eng.findings = [finding]

        result = VerifyRunner(eng)._post_worker_verify({'waf': {}})

        self.assertIs(result, vr)
        self.assertEqual(eng.findings, ['f1'])
        eng.emit_pipeline_event.assert_called_once()

    def test_disabled_no_chain_detect(self):
        eng = _make_engine(config={'verbose': False, 'modules': {}})
        eng.findings = [MagicMock()]
        self.assertIsNone(VerifyRunner(eng)._post_worker_verify(None))

    def test_disabled_no_findings(self):
        eng = _make_engine(config={'verbose': False, 'modules': {'chain_detect': True}})
        eng.findings = []
        self.assertIsNone(VerifyRunner(eng)._post_worker_verify(None))

    @patch('core.post_worker_verifier.PostWorkerVerifier', side_effect=RuntimeError('x'))
    def test_exception(self, _):
        eng = _make_engine(config={'verbose': True, 'modules': {'chain_detect': True}})
        eng.findings = [MagicMock()]
        self.assertIsNone(VerifyRunner(eng)._post_worker_verify(None))


class TestExploitSearch(unittest.TestCase):

    @patch('core.exploit_searcher.ExploitSearcher')
    def test_enabled(self, MockES):
        enriched = [MagicMock()]
        MockES.return_value.run.return_value = enriched

        eng = _make_engine(config={'verbose': False, 'modules': {'exploit_search': True}})
        eng.findings = [MagicMock()]
        VerifyRunner(eng)._exploit_search()

        self.assertEqual(eng.findings, enriched)

    def test_disabled_module(self):
        eng = _make_engine(config={'verbose': False, 'modules': {}})
        eng.findings = [MagicMock()]
        original = eng.findings.copy()
        VerifyRunner(eng)._exploit_search()
        self.assertEqual(eng.findings, original)

    def test_disabled_no_findings(self):
        eng = _make_engine(config={'verbose': False, 'modules': {'exploit_search': True}})
        eng.findings = []
        VerifyRunner(eng)._exploit_search()

    @patch('core.exploit_searcher.ExploitSearcher', side_effect=RuntimeError('fail'))
    def test_exception(self, _):
        eng = _make_engine(config={'verbose': True, 'modules': {'exploit_search': True}})
        eng.findings = [MagicMock()]
        # Should not raise
        VerifyRunner(eng)._exploit_search()


# ===========================================================================
# ReportResult
# ===========================================================================

class TestReportResultDefaults(unittest.TestCase):
    def test_defaults(self):
        r = ReportResult()
        self.assertIsNone(r.attack_map_result)
        self.assertFalse(r.output_phase_success)


# ===========================================================================
# ReportRunner
# ===========================================================================

class TestReportRunnerRun(unittest.TestCase):

    @patch('core.runners.report_runner.ReportRunner._attack_map')
    @patch('core.runners.report_runner.ReportRunner._output_phase')
    def test_stores_enrichment_data(self, mock_output, mock_map):
        mock_output.return_value = True
        mock_map.return_value = {'nodes': 5}

        eng = _make_engine()
        chains = ['chain1']
        shield = {'waf': {}}
        rip = {'origin_ip': '1.1.1.1'}
        agent = {'result': True}

        result = ReportRunner(eng).run(chains, shield, rip, agent)

        self.assertEqual(eng._exploit_chains, chains)
        self.assertEqual(eng._origin_result, rip)
        self.assertEqual(eng._agent_result, agent)
        self.assertTrue(result.output_phase_success)
        self.assertEqual(result.attack_map_result, {'nodes': 5})


class TestOutputPhase(unittest.TestCase):

    @patch('core.output_phase.OutputPhase')
    def test_success(self, MockOP):
        eng = _make_engine(config={'verbose': False, 'format': 'json', 'modules': {}})
        eng.findings = ['f1']
        result = ReportRunner(eng)._output_phase([], None, None, None)

        self.assertTrue(result)
        MockOP.return_value.run.assert_called_once()
        call_kwargs = MockOP.return_value.run.call_args[1]
        self.assertEqual(call_kwargs['report_format'], 'json')

    @patch('core.output_phase.OutputPhase', side_effect=RuntimeError('err'))
    def test_failure_with_db_fallback(self, _):
        eng = _make_engine(config={'verbose': True, 'modules': {}})
        eng.findings = ['f1']
        eng.scan_id = 'scan-1'
        eng.end_time = 123

        result = ReportRunner(eng)._output_phase([], None, None, None)

        self.assertFalse(result)
        eng.db.update_scan.assert_called_once_with(
            'scan-1', end_time=123, findings_count=1, total_requests=0)

    @patch('core.output_phase.OutputPhase', side_effect=RuntimeError('err'))
    def test_failure_without_db(self, _):
        eng = _make_engine(config={'verbose': False, 'modules': {}})
        eng.db = None
        eng.findings = []

        result = ReportRunner(eng)._output_phase([], None, None, None)
        self.assertFalse(result)

    @patch('core.output_phase.OutputPhase', side_effect=RuntimeError('err'))
    def test_db_fallback_also_fails(self, _):
        eng = _make_engine(config={'verbose': True, 'modules': {}})
        eng.findings = ['f1']
        eng.scan_id = 's1'
        eng.end_time = 0
        eng.db.update_scan.side_effect = RuntimeError('db error')

        result = ReportRunner(eng)._output_phase([], None, None, None)
        self.assertFalse(result)

    @patch('core.output_phase.OutputPhase')
    def test_default_format_html(self, MockOP):
        eng = _make_engine(config={'verbose': False, 'modules': {}})
        eng.findings = []
        ReportRunner(eng)._output_phase([], None, None, None)

        call_kwargs = MockOP.return_value.run.call_args[1]
        self.assertEqual(call_kwargs['report_format'], 'html')


class TestAttackMap(unittest.TestCase):

    @patch('core.attack_map.AttackMapBuilder')
    def test_enabled_with_findings(self, MockAMB):
        map_data = {'summary': {'total_nodes': 5, 'critical_paths': 1, 'zero_click_paths': 0}}
        MockAMB.return_value.run.return_value = map_data

        eng = _make_engine(config={'verbose': False,
                                   'modules': {'attack_map': True, 'exploit_search': True}})
        eng.findings = [MagicMock()]

        result = ReportRunner(eng)._attack_map([])

        self.assertEqual(result, map_data)
        self.assertEqual(eng._attack_map, map_data)
        eng.emit_pipeline_event.assert_called_once()

    def test_disabled_no_attack_map(self):
        eng = _make_engine(config={'verbose': False, 'modules': {}})
        eng.findings = [MagicMock()]
        self.assertIsNone(ReportRunner(eng)._attack_map([]))

    def test_disabled_no_findings(self):
        eng = _make_engine(config={'verbose': False, 'modules': {'attack_map': True}})
        eng.findings = []
        self.assertIsNone(ReportRunner(eng)._attack_map([]))

    @patch('core.attack_map.AttackMapBuilder')
    @patch('core.exploit_searcher.ExploitSearcher')
    def test_auto_enable_exploit_search(self, MockES, MockAMB):
        MockES.return_value.run.return_value = [MagicMock()]
        MockAMB.return_value.run.return_value = {'summary': {
            'total_nodes': 0, 'critical_paths': 0, 'zero_click_paths': 0}}

        eng = _make_engine(config={'verbose': False,
                                   'modules': {'attack_map': True}})
        eng.findings = [MagicMock()]

        ReportRunner(eng)._attack_map([])

        MockES.assert_called_once()
        MockES.return_value.run.assert_called_once()

    @patch('core.attack_map.AttackMapBuilder', side_effect=RuntimeError('map fail'))
    def test_exception(self, _):
        eng = _make_engine(config={'verbose': True,
                                   'modules': {'attack_map': True, 'exploit_search': True}})
        eng.findings = [MagicMock()]
        self.assertIsNone(ReportRunner(eng)._attack_map([]))

    @patch('core.attack_map.AttackMapBuilder')
    def test_exploit_chains_passed(self, MockAMB):
        MockAMB.return_value.run.return_value = {'summary': {
            'total_nodes': 0, 'critical_paths': 0, 'zero_click_paths': 0}}

        eng = _make_engine(config={'verbose': False,
                                   'modules': {'attack_map': True, 'exploit_search': True}})
        eng.findings = [MagicMock()]
        chains = ['c1', 'c2']

        ReportRunner(eng)._attack_map(chains)
        call_kwargs = MockAMB.return_value.run.call_args[1]
        self.assertEqual(call_kwargs['exploit_chains'], chains)

    @patch('core.attack_map.AttackMapBuilder')
    @patch('core.exploit_searcher.ExploitSearcher', side_effect=RuntimeError('x'))
    def test_auto_exploit_search_failure_continues(self, MockES, MockAMB):
        MockAMB.return_value.run.return_value = {'summary': {
            'total_nodes': 0, 'critical_paths': 0, 'zero_click_paths': 0}}

        eng = _make_engine(config={'verbose': True,
                                   'modules': {'attack_map': True}})
        eng.findings = [MagicMock()]

        result = ReportRunner(eng)._attack_map([])
        # AttackMapBuilder still runs even though ExploitSearcher failed
        MockAMB.return_value.run.assert_called_once()
        self.assertIsNotNone(result)


# ===========================================================================
# Regulated Pipeline: origin IP → discovery flow
# ===========================================================================

class TestReconRunnerOriginIPFlow(unittest.TestCase):
    """Test that the recon runner uses origin IP for crawling / discovery."""

    @patch('core.runners.recon_runner.ReconRunner._legacy_discovery')
    @patch('core.runners.recon_runner.ReconRunner._passive_recon')
    @patch('core.runners.recon_runner.ReconRunner._real_ip_discover')
    @patch('core.runners.recon_runner.ReconRunner._shield_detect')
    def test_origin_ip_builds_effective_target(self, mock_shield, mock_rip,
                                                mock_passive, mock_legacy):
        """When real IP is found, _legacy_discovery receives an origin-IP URL."""
        mock_shield.return_value = {'cdn': {'detected': True}}
        mock_rip.return_value = {'origin_ip': '93.184.216.34'}
        mock_passive.return_value = None
        mock_legacy.return_value = (set(), [], [])

        eng = _make_engine()
        ReconRunner(eng).run('http://example.com/path')

        call_kwargs = mock_legacy.call_args
        effective = call_kwargs[1]['effective_target']
        self.assertIn('93.184.216.34', effective)
        self.assertNotIn('example.com', effective)

    @patch('core.runners.recon_runner.ReconRunner._legacy_discovery')
    @patch('core.runners.recon_runner.ReconRunner._passive_recon')
    @patch('core.runners.recon_runner.ReconRunner._real_ip_discover')
    @patch('core.runners.recon_runner.ReconRunner._shield_detect')
    def test_no_origin_ip_uses_original_target(self, mock_shield, mock_rip,
                                                mock_passive, mock_legacy):
        """Without real IP, effective_target equals the original target."""
        mock_shield.return_value = None
        mock_rip.return_value = None
        mock_passive.return_value = None
        mock_legacy.return_value = (set(), [], [])

        eng = _make_engine()
        ReconRunner(eng).run('http://target.com')

        call_kwargs = mock_legacy.call_args
        self.assertEqual(call_kwargs[1]['effective_target'], 'http://target.com')

    @patch('core.runners.recon_runner.ReconRunner._passive_recon')
    @patch('core.runners.recon_runner.ReconRunner._real_ip_discover')
    @patch('core.runners.recon_runner.ReconRunner._shield_detect')
    def test_fanout_receives_effective_target(self, mock_shield, mock_rip,
                                               mock_passive):
        """Passive recon fan-out should receive the effective target URL."""
        mock_shield.return_value = {'cdn': {'detected': True}}
        mock_rip.return_value = {'origin_ip': '10.0.0.1'}
        fanout = MagicMock()
        fanout.urls = set()
        fanout.forms = []
        fanout.params = []
        mock_passive.return_value = fanout

        eng = _make_engine()
        ReconRunner(eng).run('http://cdn-target.com')

        # Passive recon should have been called with the origin-IP URL
        called_target = mock_passive.call_args[0][0]
        self.assertIn('10.0.0.1', called_target)


class TestLegacyDiscoveryFuzzerStep(unittest.TestCase):
    """Test that fuzzer discovery is integrated into legacy discovery."""

    @patch('modules.fuzzer.FuzzerModule.discover')
    @patch('utils.crawler.Crawler')
    def test_fuzzer_runs_when_discovery_enabled(self, MockCrawler, mock_discover):
        MockCrawler.return_value.crawl.return_value = ({'http://a'}, [], [])
        MockCrawler.return_value.endpoint_graph = None
        mock_discover.return_value = {
            'urls': {'http://a/admin'},
            'parameters': [('http://a', 'get', 'debug', 'test123', 'fuzzer')],
        }

        eng = _make_engine(config={
            'verbose': False, 'depth': 2,
            'modules': {'discovery': True}})
        urls, forms, params = ReconRunner(eng)._legacy_discovery(
            'http://a', effective_target='http://a', shield_profile=None)

        mock_discover.assert_called_once_with('http://a')
        self.assertIn('http://a/admin', urls)
        param_names = [p[2] for p in params]
        self.assertIn('debug', param_names)

    @patch('modules.fuzzer.FuzzerModule.discover')
    @patch('utils.crawler.Crawler')
    def test_fuzzer_runs_when_fuzzer_flag_enabled(self, MockCrawler, mock_discover):
        MockCrawler.return_value.crawl.return_value = (set(), [], [])
        MockCrawler.return_value.endpoint_graph = None
        mock_discover.return_value = {'urls': set(), 'parameters': []}

        eng = _make_engine(config={
            'verbose': False, 'depth': 2,
            'modules': {'fuzzer': True}})
        ReconRunner(eng)._legacy_discovery(
            'http://t', effective_target='http://t', shield_profile=None)

        mock_discover.assert_called_once()

    @patch('utils.crawler.Crawler')
    def test_fuzzer_not_run_when_both_disabled(self, MockCrawler):
        MockCrawler.return_value.crawl.return_value = (set(), [], [])
        MockCrawler.return_value.endpoint_graph = None

        eng = _make_engine(config={
            'verbose': False, 'depth': 2,
            'modules': {}})
        urls, forms, params = ReconRunner(eng)._legacy_discovery(
            'http://t', effective_target='http://t', shield_profile=None)

        # Fuzzer should not have been invoked (no discovery/fuzzer flags)
        self.assertEqual(len(params), 0)

    @patch('modules.fuzzer.FuzzerModule.discover')
    @patch('utils.crawler.Crawler')
    def test_fuzzer_uses_effective_target(self, MockCrawler, mock_discover):
        """Fuzzer should receive the origin-IP effective target."""
        MockCrawler.return_value.crawl.return_value = (set(), [], [])
        MockCrawler.return_value.endpoint_graph = None
        mock_discover.return_value = {'urls': set(), 'parameters': []}

        eng = _make_engine(config={
            'verbose': False, 'depth': 2,
            'modules': {'discovery': True}})
        ReconRunner(eng)._legacy_discovery(
            'http://target.com',
            effective_target='http://93.184.216.34',
            shield_profile={'waf': {'detected': True}})

        mock_discover.assert_called_once_with('http://93.184.216.34')

    @patch('modules.fuzzer.FuzzerModule.discover', side_effect=RuntimeError('boom'))
    @patch('utils.crawler.Crawler')
    def test_fuzzer_exception_does_not_break_pipeline(self, MockCrawler, _):
        MockCrawler.return_value.crawl.return_value = ({'http://a'}, [], [])
        MockCrawler.return_value.endpoint_graph = None

        eng = _make_engine(config={
            'verbose': True, 'depth': 2,
            'modules': {'discovery': True}})
        # Should not raise
        urls, _, _ = ReconRunner(eng)._legacy_discovery(
            'http://a', effective_target='http://a', shield_profile=None)
        self.assertIn('http://a', urls)

    @patch('utils.crawler.Crawler')
    def test_crawl_uses_effective_target(self, MockCrawler):
        """Crawler should receive the origin-IP effective target."""
        MockCrawler.return_value.crawl.return_value = (set(), [], [])
        MockCrawler.return_value.endpoint_graph = None

        eng = _make_engine(config={
            'verbose': False, 'depth': 2,
            'modules': {}})
        ReconRunner(eng)._legacy_discovery(
            'http://example.com',
            effective_target='http://10.0.0.5')

        crawl_call = MockCrawler.return_value.crawl.call_args
        self.assertEqual(crawl_call[0][0], 'http://10.0.0.5')

    @patch('modules.port_scanner.PortScanner')
    @patch('utils.crawler.Crawler')
    def test_port_scan_uses_effective_target(self, MockCrawler, MockPort):
        """Port scanner should use origin IP hostname."""
        MockCrawler.return_value.crawl.return_value = (set(), [], [])
        MockCrawler.return_value.endpoint_graph = None
        MockPort.return_value.run.return_value = []

        eng = _make_engine(config={
            'verbose': False, 'depth': 1,
            'modules': {'ports': '80,443'}})
        ReconRunner(eng)._legacy_discovery(
            'http://example.com',
            effective_target='http://10.0.0.5')

        port_call = MockPort.return_value.run.call_args
        self.assertEqual(port_call[0][0], '10.0.0.5')


if __name__ == '__main__':
    unittest.main()
