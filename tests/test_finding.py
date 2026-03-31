#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the Finding dataclass and engine helpers (core/engine.py)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.engine import Finding


class TestFinding(unittest.TestCase):

    def test_default_method_is_get(self):
        f = Finding()
        self.assertEqual(f.method, 'GET')

    def test_auto_mitre_cwe(self):
        f = Finding(technique='SQL Injection (Error-based)')
        self.assertTrue(f.mitre_id)
        self.assertTrue(f.cwe_id)

    def test_auto_remediation(self):
        f = Finding(technique='SQL Injection')
        self.assertIn('parameterized', f.remediation.lower())

    def test_no_clobbering_explicit_mitre(self):
        f = Finding(technique='SQL Injection', mitre_id='T9999', cwe_id='CWE-0000')
        self.assertEqual(f.mitre_id, 'T9999')
        self.assertEqual(f.cwe_id, 'CWE-0000')

    def test_method_field_present(self):
        f = Finding(technique='XSS', url='http://x', method='POST')
        self.assertEqual(f.method, 'POST')


if __name__ == '__main__':
    unittest.main()
