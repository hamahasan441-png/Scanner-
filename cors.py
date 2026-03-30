#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - CORS Module
CORS Misconfiguration detection
"""

import re
from config import Colors


class CORSModule:
    """CORS Testing Module"""
    
    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.name = "CORS Misconfiguration"
    
    def test(self, url: str, method: str, param: str, value: str):
        """Test for CORS misconfiguration"""
        pass  # CORS is tested at URL level
    
    def test_url(self, url: str):
        """Test URL for CORS misconfiguration"""
        # Test with malicious origin
        malicious_origins = [
            'https://evil.com',
            'http://evil.com',
            'https://attacker.com',
            'null',
            'file://',
            'http://localhost',
            'http://127.0.0.1',
            'https://' + urlparse(url).netloc + '.evil.com',
        ]
        
        for origin in malicious_origins:
            try:
                headers = {'Origin': origin}
                response = self.requester.request(url, 'GET', headers=headers)
                
                if not response:
                    continue
                
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')
                acam = response.headers.get('Access-Control-Allow-Methods', '')
                
                # Check for misconfigurations
                if acao == '*':
                    from core.engine import Finding
                    finding = Finding(
                        technique="CORS Misconfiguration (Wildcard)",
                        url=url,
                        severity='MEDIUM',
                        confidence=0.8,
                        param='',
                        payload='Origin: ' + origin,
                        evidence="Access-Control-Allow-Origin: *",
                    )
                    self.engine.add_finding(finding)
                    return
                
                if acao == origin:
                    if acac.lower() == 'true':
                        from core.engine import Finding
                        finding = Finding(
                            technique="CORS Misconfiguration (Credentials)",
                            url=url,
                            severity='HIGH',
                            confidence=0.9,
                            param='',
                            payload='Origin: ' + origin,
                            evidence=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: true",
                        )
                        self.engine.add_finding(finding)
                        return
                    else:
                        from core.engine import Finding
                        finding = Finding(
                            technique="CORS Misconfiguration (Reflected Origin)",
                            url=url,
                            severity='MEDIUM',
                            confidence=0.7,
                            param='',
                            payload='Origin: ' + origin,
                            evidence=f"Access-Control-Allow-Origin: {acao}",
                        )
                        self.engine.add_finding(finding)
                        return
                        
            except Exception as e:
                if self.engine.config.get('verbose'):
                    print(f"{Colors.error(f'CORS test error: {e}')}")
    
    def test_preflight(self, url: str):
        """Test CORS preflight response"""
        try:
            headers = {
                'Origin': 'https://evil.com',
                'Access-Control-Request-Method': 'DELETE',
                'Access-Control-Request-Headers': 'X-Custom-Header',
            }
            
            response = self.requester.request(url, 'OPTIONS', headers=headers)
            
            if response:
                acam = response.headers.get('Access-Control-Allow-Methods', '')
                
                if 'DELETE' in acam or 'PUT' in acam or 'PATCH' in acam:
                    from core.engine import Finding
                    finding = Finding(
                        technique="CORS Misconfiguration (Dangerous Methods)",
                        url=url,
                        severity='MEDIUM',
                        confidence=0.7,
                        param='',
                        payload='OPTIONS request',
                        evidence=f"Dangerous methods allowed: {acam}",
                    )
                    self.engine.add_finding(finding)
                    
        except Exception as e:
            if self.engine.config.get('verbose'):
                print(f"{Colors.error(f'CORS preflight test error: {e}')}")


from urllib.parse import urlparse
