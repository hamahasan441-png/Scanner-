#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for core/payload_generator.py – Payload Generator (Partition 2)."""

import unittest
from dataclasses import dataclass, field


@dataclass
class MockFinding:
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
    cvss: float = 0.0
    extracted_data: str = ''
    signals: dict = field(default_factory=dict)
    priority: float = 0.0
    remediation: str = ''


class TestSQLiPayloads(unittest.TestCase):
    """Test SQL injection payload generation."""

    def setUp(self):
        from core.payload_generator import PayloadGenerator
        self.gen = PayloadGenerator()

    def test_union_payload_default(self):
        payload = self.gen.sqli_union_payload(5, inject_col=2, subquery='SELECT version()')
        self.assertIn('UNION SELECT', payload)
        self.assertIn('NULL', payload)
        self.assertIn('SELECT version()', payload)

    def test_time_payload_mysql(self):
        payload = self.gen.sqli_time_payload('mysql', delay=5)
        self.assertIn('SLEEP(5)', payload)

    def test_time_payload_postgresql(self):
        payload = self.gen.sqli_time_payload('postgresql', delay=3)
        self.assertIn('pg_sleep(3)', payload)

    def test_time_payload_mssql(self):
        payload = self.gen.sqli_time_payload('mssql', delay=5)
        self.assertIn('WAITFOR DELAY', payload)

    def test_error_payload_mysql(self):
        payload = self.gen.sqli_error_payload('mysql')
        self.assertIn('EXTRACTVALUE', payload)

    def test_error_payload_postgresql(self):
        payload = self.gen.sqli_error_payload('postgresql')
        self.assertIn('CAST', payload)

    def test_error_payload_unknown_returns_empty(self):
        payload = self.gen.sqli_error_payload('unknowndb')
        self.assertEqual(payload, '')


class TestXSSPayloads(unittest.TestCase):
    """Test XSS payload generation."""

    def setUp(self):
        from core.payload_generator import PayloadGenerator
        self.gen = PayloadGenerator(callback_host='evil.com')

    def test_cookie_stealer(self):
        payload = self.gen.xss_cookie_stealer()
        self.assertIn('evil.com', payload)
        self.assertIn('document.cookie', payload)
        self.assertIn('<script>', payload)

    def test_cookie_stealer_custom_callback(self):
        payload = self.gen.xss_cookie_stealer(callback='attacker.org')
        self.assertIn('attacker.org', payload)

    def test_keylogger(self):
        payload = self.gen.xss_keylogger()
        self.assertIn('onkeypress', payload)
        self.assertIn('evil.com', payload)

    def test_polyglot(self):
        payload = self.gen.xss_polyglot()
        self.assertIn('alert', payload)
        self.assertTrue(len(payload) > 50)


class TestCMDiPayloads(unittest.TestCase):
    """Test command injection payload generation."""

    def setUp(self):
        from core.payload_generator import PayloadGenerator
        self.gen = PayloadGenerator(lhost='10.0.0.1', lport=4444)

    def test_reverse_shell_bash(self):
        payload = self.gen.reverse_shell('bash')
        self.assertIn('10.0.0.1', payload)
        self.assertIn('4444', payload)
        self.assertIn('bash', payload)

    def test_reverse_shell_python(self):
        payload = self.gen.reverse_shell('python')
        self.assertIn('socket', payload)
        self.assertIn('10.0.0.1', payload)

    def test_reverse_shell_nc(self):
        payload = self.gen.reverse_shell('nc')
        self.assertIn('nc', payload)
        self.assertIn('10.0.0.1', payload)

    def test_reverse_shell_custom_host(self):
        payload = self.gen.reverse_shell('bash', lhost='192.168.1.1', lport=9999)
        self.assertIn('192.168.1.1', payload)
        self.assertIn('9999', payload)

    def test_data_exfil_curl(self):
        self.gen.callback = 'exfil.example.com'
        payload = self.gen.data_exfil_payload('curl')
        self.assertIn('exfil.example.com', payload)
        self.assertIn('curl', payload)

    def test_reverse_shell_unknown_type(self):
        payload = self.gen.reverse_shell('unknown_shell')
        self.assertEqual(payload, '')


class TestSSTIPayloads(unittest.TestCase):
    """Test SSTI payload generation."""

    def setUp(self):
        from core.payload_generator import PayloadGenerator
        self.gen = PayloadGenerator()

    def test_jinja2_rce(self):
        payload = self.gen.ssti_rce('jinja2', 'id')
        self.assertIn('id', payload)
        self.assertIn('popen', payload)

    def test_twig_rce(self):
        payload = self.gen.ssti_rce('twig', 'whoami')
        self.assertIn('whoami', payload)
        self.assertIn('system', payload)

    def test_freemarker_rce(self):
        payload = self.gen.ssti_rce('freemarker', 'id')
        self.assertIn('Execute', payload)

    def test_ssti_file_read_jinja2(self):
        payload = self.gen.ssti_file_read('jinja2', '/etc/passwd')
        self.assertIn('/etc/passwd', payload)

    def test_ssti_unknown_engine(self):
        payload = self.gen.ssti_rce('unknown_engine', 'id')
        self.assertEqual(payload, '')


class TestWebShellGeneration(unittest.TestCase):
    """Test web shell generation."""

    def setUp(self):
        from core.payload_generator import PayloadGenerator
        self.gen = PayloadGenerator()

    def test_php_mini_shell(self):
        shell = self.gen.web_shell('php_mini')
        self.assertIn('<?php', shell)
        self.assertIn('system', shell)

    def test_php_eval_shell(self):
        shell = self.gen.web_shell('php_eval')
        self.assertIn('eval', shell)

    def test_php_stealth_with_key(self):
        shell = self.gen.web_shell('php_stealth', key='mysecret')
        self.assertIn('<?php', shell)
        self.assertNotIn('{{key}}', shell)
        # Should contain md5 of 'mysecret'
        import hashlib
        expected_hash = hashlib.md5(b'mysecret').hexdigest()
        self.assertIn(expected_hash, shell)

    def test_jsp_shell(self):
        shell = self.gen.web_shell('jsp_mini')
        self.assertIn('Runtime', shell)

    def test_asp_shell(self):
        shell = self.gen.web_shell('asp_mini')
        self.assertIn('WSCRIPT', shell)

    def test_unknown_shell_fallback(self):
        shell = self.gen.web_shell('nonexistent_type')
        self.assertIn('<?php', shell)  # Should fallback to php_mini


class TestCVEExploits(unittest.TestCase):
    """Test CVE exploit stub generation."""

    def setUp(self):
        from core.payload_generator import PayloadGenerator
        self.gen = PayloadGenerator(callback_host='attacker.com')

    def test_log4shell(self):
        result = self.gen.cve_exploit('CVE-2021-44228')
        self.assertEqual(result['cve'], 'CVE-2021-44228')
        self.assertIn('jndi', result['payload'])
        self.assertIn('attacker.com', result['payload'])

    def test_spring4shell(self):
        result = self.gen.cve_exploit('CVE-2022-22965')
        self.assertEqual(result['cve'], 'CVE-2022-22965')
        self.assertIn('classLoader', result['payload'])

    def test_shellshock(self):
        result = self.gen.cve_exploit('CVE-2014-6271', cmd='whoami')
        self.assertIn('whoami', result['payload'])

    def test_unknown_cve(self):
        result = self.gen.cve_exploit('CVE-9999-99999')
        self.assertIn('No built-in', result['description'])

    def test_search_by_name(self):
        result = self.gen.cve_exploit('log4j')
        self.assertEqual(result['cve'], 'CVE-2021-44228')


class TestPOCGeneration(unittest.TestCase):
    """Test POC generation for findings."""

    def setUp(self):
        from core.payload_generator import PayloadGenerator
        self.gen = PayloadGenerator()

    def test_poc_sqli(self):
        finding = MockFinding(
            technique='SQL Injection', url='http://test.com/page?id=1',
            param='id', payload="' OR 1=1--", method='GET', severity='HIGH',
        )
        poc = self.gen.generate_poc(finding)
        self.assertEqual(poc['family'], 'sqli')
        self.assertIn('exploit_payloads', poc)
        self.assertIn('error_based', poc['exploit_payloads'])
        self.assertIn('curl_command', poc)
        self.assertIn('steps', poc)

    def test_poc_xss(self):
        finding = MockFinding(
            technique='XSS', url='http://test.com/search',
            param='q', payload='<script>alert(1)</script>',
            severity='MEDIUM',
        )
        poc = self.gen.generate_poc(finding)
        self.assertEqual(poc['family'], 'xss')
        self.assertIn('cookie_stealer', poc['exploit_payloads'])

    def test_poc_cmdi(self):
        finding = MockFinding(
            technique='Command Injection', url='http://test.com/ping',
            param='host', payload='; id', severity='CRITICAL',
        )
        poc = self.gen.generate_poc(finding)
        self.assertEqual(poc['family'], 'cmdi')
        self.assertIn('reverse_shell_bash', poc['exploit_payloads'])

    def test_poc_ssti(self):
        finding = MockFinding(
            technique='SSTI', url='http://test.com/template',
            param='name', payload='{{7*7}}', severity='HIGH',
        )
        poc = self.gen.generate_poc(finding)
        self.assertEqual(poc['family'], 'ssti')
        self.assertIn('jinja2_rce', poc['exploit_payloads'])

    def test_poc_lfi(self):
        finding = MockFinding(
            technique='Local File Inclusion', url='http://test.com/read',
            param='file', payload='../../../etc/passwd', severity='HIGH',
        )
        poc = self.gen.generate_poc(finding)
        self.assertEqual(poc['family'], 'lfi')
        self.assertIn('etc_passwd', poc['exploit_payloads'])

    def test_poc_upload(self):
        finding = MockFinding(
            technique='File Upload', url='http://test.com/upload',
            param='file', severity='CRITICAL',
        )
        poc = self.gen.generate_poc(finding)
        self.assertEqual(poc['family'], 'upload')
        self.assertIn('php_shell', poc['exploit_payloads'])

    def test_poc_cve(self):
        finding = MockFinding(
            technique='CVE-2021-44228 Log4Shell',
            url='http://test.com/api',
            param='header', severity='CRITICAL',
        )
        poc = self.gen.generate_poc(finding)
        self.assertEqual(poc['family'], 'cve')
        self.assertIn('exploit_payloads', poc)

    def test_poc_curl_get(self):
        finding = MockFinding(
            technique='XSS', url='http://test.com/page',
            param='q', payload='<script>x</script>', method='GET',
        )
        poc = self.gen.generate_poc(finding)
        self.assertIn('curl', poc['curl_command'])
        self.assertIn('-v', poc['curl_command'])

    def test_poc_curl_post(self):
        finding = MockFinding(
            technique='SQL Injection', url='http://test.com/login',
            param='user', payload="' OR 1=1--", method='POST',
        )
        poc = self.gen.generate_poc(finding)
        self.assertIn('POST', poc['curl_command'])
        self.assertIn('-d', poc['curl_command'])

    def test_poc_steps_generated(self):
        finding = MockFinding(
            technique='SQL Injection', url='http://test.com/',
            param='id', payload="'", severity='HIGH',
        )
        poc = self.gen.generate_poc(finding)
        self.assertTrue(len(poc['steps']) >= 3)
        self.assertIn('Navigate', poc['steps'][0])

    def test_poc_has_timestamp(self):
        finding = MockFinding(technique='XSS', url='http://x.com', param='q')
        poc = self.gen.generate_poc(finding)
        self.assertIn('timestamp', poc)

    def test_poc_unknown_family(self):
        finding = MockFinding(technique='Unknown Type', url='http://x.com', param='x')
        poc = self.gen.generate_poc(finding)
        self.assertIn('Vulnerability confirmed', poc['description'])


if __name__ == '__main__':
    unittest.main()
