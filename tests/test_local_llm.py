#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the Local LLM module (core/local_llm.py)."""

import os
import sys
import json
import tempfile
import unittest
from unittest.mock import MagicMock, patch, PropertyMock


# ===========================================================================
# Tests for model management functions
# ===========================================================================

class TestModelPath(unittest.TestCase):
    """Test model path and status helpers."""

    def test_get_model_path_default(self):
        from core.local_llm import get_model_path, DEFAULT_MODEL_FILE, MODELS_DIR
        path = get_model_path()
        self.assertEqual(path, os.path.join(MODELS_DIR, DEFAULT_MODEL_FILE))

    def test_get_model_path_custom(self):
        from core.local_llm import get_model_path, MODELS_DIR
        path = get_model_path('custom-model.gguf')
        self.assertEqual(path, os.path.join(MODELS_DIR, 'custom-model.gguf'))

    def test_is_model_downloaded_false_when_missing(self):
        from core.local_llm import is_model_downloaded
        self.assertFalse(is_model_downloaded('nonexistent-model-12345.gguf'))

    def test_is_model_downloaded_false_when_too_small(self):
        """A file under 100MB is not considered a valid model."""
        from core.local_llm import is_model_downloaded, MODELS_DIR
        os.makedirs(MODELS_DIR, exist_ok=True)
        small_file = os.path.join(MODELS_DIR, '_test_tiny.gguf')
        try:
            with open(small_file, 'wb') as f:
                f.write(b'x' * 100)
            self.assertFalse(is_model_downloaded('_test_tiny.gguf'))
        finally:
            if os.path.isfile(small_file):
                os.remove(small_file)


class TestDownloadModel(unittest.TestCase):
    """Test model download logic."""

    @patch('core.local_llm.is_model_downloaded', return_value=True)
    def test_skip_download_when_already_present(self, mock_check):
        from core.local_llm import download_model
        path = download_model()
        # Should return the path without downloading
        self.assertTrue(path.endswith('.gguf'))
        mock_check.assert_called_once()

    @patch('core.local_llm.is_model_downloaded', return_value=False)
    @patch('requests.get')
    def test_download_handles_network_error(self, mock_get, mock_check):
        import requests
        mock_get.side_effect = requests.RequestException('Network error')
        from core.local_llm import download_model
        result = download_model()
        self.assertEqual(result, '')


# ===========================================================================
# Tests for LocalLLM class
# ===========================================================================

class TestLocalLLMInit(unittest.TestCase):
    """Test LocalLLM initialization and lifecycle."""

    def test_default_init(self):
        from core.local_llm import LocalLLM, DEFAULT_CTX_SIZE, DEFAULT_N_THREADS
        llm = LocalLLM()
        self.assertEqual(llm.n_ctx, DEFAULT_CTX_SIZE)
        self.assertEqual(llm.n_threads, DEFAULT_N_THREADS)
        self.assertFalse(llm.is_loaded)

    def test_custom_init(self):
        from core.local_llm import LocalLLM
        llm = LocalLLM(
            model_path='/tmp/test.gguf',
            n_ctx=4096,
            n_threads=4,
            n_gpu_layers=10,
            verbose=True,
        )
        self.assertEqual(llm.model_path, '/tmp/test.gguf')
        self.assertEqual(llm.n_ctx, 4096)
        self.assertEqual(llm.n_threads, 4)
        self.assertEqual(llm.n_gpu_layers, 10)
        self.assertTrue(llm.verbose)

    @patch('core.local_llm.LocalLLM.is_available', return_value=False)
    def test_is_available_false(self, mock_avail):
        from core.local_llm import LocalLLM
        self.assertFalse(LocalLLM.is_available())

    def test_unload(self):
        from core.local_llm import LocalLLM
        llm = LocalLLM()
        llm._llm = MagicMock()
        self.assertTrue(llm.is_loaded)
        llm.unload()
        self.assertFalse(llm.is_loaded)


class TestLocalLLMAnalysis(unittest.TestCase):
    """Test LLM analysis methods with mocked inference."""

    def _make_llm_with_mock(self, response_text='Test response'):
        from core.local_llm import LocalLLM
        llm = LocalLLM()
        # Mock the internal llama model
        mock_model = MagicMock()
        mock_model.return_value = {
            'choices': [{'text': response_text}],
        }
        llm._llm = mock_model
        return llm

    def test_chat_returns_text(self):
        llm = self._make_llm_with_mock('Hello from Qwen!')
        result = llm.chat('system prompt', 'user message')
        self.assertEqual(result, 'Hello from Qwen!')

    def test_generate_empty_on_no_model(self):
        from core.local_llm import LocalLLM
        llm = LocalLLM()
        # _llm is None and ensure_ready will fail
        with patch.object(llm, 'load', return_value=False):
            result = llm._generate('test prompt')
        self.assertEqual(result, '')

    def test_analyze_finding(self):
        response = (
            "1. Risk: High risk of data breach.\n"
            "2. Exploitation: Attacker could extract database.\n"
            "3. Remediation: Use parameterized queries.\n"
            "4. False positive likelihood: low"
        )
        llm = self._make_llm_with_mock(response)
        result = llm.analyze_finding({
            'technique': 'SQL Injection',
            'url': 'https://test.com',
            'param': 'id',
            'payload': "' OR 1=1 --",
            'evidence': 'SQL error',
            'severity': 'HIGH',
            'confidence': 0.9,
        })
        self.assertIn('llm_analysis', result)
        self.assertIn('model', result)
        self.assertEqual(result['model'], 'qwen2.5-7b-instruct-q4_k_m')
        self.assertIn('Risk', result['llm_analysis'])

    def test_suggest_payloads(self):
        response = (
            "' UNION SELECT NULL,NULL --\n"
            "' OR 1=1 --\n"
            "' AND SLEEP(5) --\n"
        )
        llm = self._make_llm_with_mock(response)
        payloads = llm.suggest_payloads('sqli', {
            'technology': 'php,mysql',
            'waf_detected': 'none',
            'param_name': 'id',
        })
        self.assertIsInstance(payloads, list)
        self.assertTrue(len(payloads) > 0)
        self.assertTrue(len(payloads) <= 5)

    def test_suggest_payloads_empty_on_no_response(self):
        from core.local_llm import LocalLLM
        llm = LocalLLM()
        llm._llm = MagicMock(return_value={'choices': [{'text': ''}]})
        payloads = llm.suggest_payloads('xss', {})
        self.assertEqual(payloads, [])

    def test_analyze_response_vulnerable(self):
        response = (
            "VULNERABLE: yes\n"
            "CONFIDENCE: 0.9\n"
            "REASON: SQL error clearly visible"
        )
        llm = self._make_llm_with_mock(response)
        result = llm.analyze_response(
            'https://test.com', 'id', "' OR 1=1 --",
            "You have an error in your SQL syntax",
        )
        self.assertTrue(result['is_vulnerable'])
        self.assertAlmostEqual(result['confidence'], 0.9)

    def test_analyze_response_not_vulnerable(self):
        response = (
            "VULNERABLE: no\n"
            "CONFIDENCE: 0.2\n"
            "REASON: Normal error page"
        )
        llm = self._make_llm_with_mock(response)
        result = llm.analyze_response(
            'https://test.com', 'q', '<script>alert(1)</script>',
            "404 Not Found",
        )
        self.assertFalse(result['is_vulnerable'])

    def test_generate_scan_summary(self):
        summary_text = "The target has critical vulnerabilities including SQL injection."
        llm = self._make_llm_with_mock(summary_text)
        result = llm.generate_scan_summary(
            findings=[
                {'technique': 'SQL Injection', 'severity': 'CRITICAL'},
                {'technique': 'XSS', 'severity': 'HIGH'},
            ],
            target='https://test.com',
            scan_duration=120.0,
        )
        self.assertIn('critical', result.lower())

    def test_classify_parameter_valid_json(self):
        response = '{"purpose": "database lookup", "likely_vulns": ["sqli"], "priority": "high"}'
        llm = self._make_llm_with_mock(response)
        result = llm.classify_parameter('id', '42', 'https://test.com/users?id=42')
        self.assertEqual(result['purpose'], 'database lookup')
        self.assertIn('sqli', result['likely_vulns'])

    def test_classify_parameter_invalid_json(self):
        llm = self._make_llm_with_mock('Not valid JSON at all')
        result = llm.classify_parameter('q', 'test', 'https://test.com/search?q=test')
        self.assertEqual(result['purpose'], 'unknown')

    def test_generate_handles_exception(self):
        from core.local_llm import LocalLLM
        llm = LocalLLM()
        mock_model = MagicMock(side_effect=RuntimeError('inference error'))
        llm._llm = mock_model
        result = llm._generate('test')
        self.assertEqual(result, '')


class TestLocalLLMEnsureReady(unittest.TestCase):
    """Test ensure_ready lifecycle."""

    @patch('core.local_llm.LocalLLM.is_available', return_value=True)
    @patch('os.path.isfile', return_value=True)
    def test_ensure_ready_when_all_present(self, mock_isfile, mock_avail):
        from core.local_llm import LocalLLM
        llm = LocalLLM(model_path='/tmp/test.gguf')
        result = llm.ensure_ready()
        self.assertTrue(result)

    @patch('core.local_llm.LocalLLM.is_available', return_value=False)
    @patch('core.local_llm.LocalLLM.install_backend', return_value=False)
    def test_ensure_ready_fails_without_backend(self, mock_install, mock_avail):
        from core.local_llm import LocalLLM
        llm = LocalLLM()
        result = llm.ensure_ready()
        self.assertFalse(result)


class TestAIEngineLocalLLM(unittest.TestCase):
    """Test AIEngine integration with local LLM."""

    def _make_engine(self):
        engine = MagicMock()
        engine.config = {'verbose': False}
        engine.context = MagicMock()
        engine.context.detected_tech = {'php', 'mysql'}
        engine.adaptive = MagicMock()
        engine.adaptive.waf_detected = False
        engine.adaptive.waf_name = ''
        engine.adaptive.signal_strength = 0.0
        return engine

    def test_get_llm_payloads_returns_empty_without_llm(self):
        from core.ai_engine import AIEngine
        engine = self._make_engine()
        engine.local_llm = None
        ai = AIEngine(engine)
        ai.local_llm = None
        result = ai.get_llm_payloads('sqli', 'id')
        self.assertEqual(result, [])

    def test_get_llm_payloads_with_llm(self):
        from core.ai_engine import AIEngine
        engine = self._make_engine()
        ai = AIEngine(engine)

        mock_llm = MagicMock()
        mock_llm.is_loaded = True
        mock_llm.suggest_payloads.return_value = ["' OR 1=1 --", "' UNION SELECT NULL --"]
        ai.local_llm = mock_llm

        result = ai.get_llm_payloads('sqli', 'id')
        self.assertEqual(len(result), 2)
        mock_llm.suggest_payloads.assert_called_once()

    def test_get_llm_payloads_handles_exception(self):
        from core.ai_engine import AIEngine
        engine = self._make_engine()
        ai = AIEngine(engine)

        mock_llm = MagicMock()
        mock_llm.is_loaded = True
        mock_llm.suggest_payloads.side_effect = RuntimeError('LLM error')
        ai.local_llm = mock_llm

        result = ai.get_llm_payloads('xss')
        self.assertEqual(result, [])


class TestDownloadProgress(unittest.TestCase):
    """Test the download progress bar helper."""

    def test_progress_bar(self):
        from core.local_llm import _download_progress
        import io
        # Just ensure it doesn't crash
        _download_progress(500, 1000)
        _download_progress(1000, 1000)
        _download_progress(0, 0)


if __name__ == '__main__':
    unittest.main()
