#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - WebSocket Injection Module
Cross-Site WebSocket Hijacking and message injection
"""

import re

from config import Colors


class WebSocketModule:
    """WebSocket Injection Testing Module"""
    
    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.name = "WebSocket Injection"
    
    def test(self, url, method, param, value):
        """Test for WebSocket vulnerabilities in parameters"""
        pass  # WebSocket tests are URL-based
    
    def test_url(self, url):
        """Test URL for WebSocket vulnerabilities"""
        self._test_cswsh(url)
        self._test_ws_injection(url)
        self._test_origin_validation(url)
        self._test_ws_protocol_abuse(url)
    
    def _test_cswsh(self, url):
        """Test for Cross-Site WebSocket Hijacking"""
        ws_url = url.replace('http://', 'ws://').replace('https://', 'wss://')
        
        try:
            response = self.requester.request(url, 'GET', headers={
                'Upgrade': 'websocket',
                'Connection': 'Upgrade',
                'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                'Sec-WebSocket-Version': '13',
                'Origin': 'https://evil.example.com',
            })
            
            if not response:
                return
            
            if response.status_code == 101 or 'upgrade' in response.headers.get('Connection', '').lower():
                from core.engine import Finding
                finding = Finding(
                    technique="WebSocket (Cross-Site Hijacking / CSWSH)",
                    url=url, severity='HIGH', confidence=0.8,
                    param='Origin', payload='https://evil.example.com',
                    evidence="WebSocket upgrade accepted from foreign origin",
                )
                self.engine.add_finding(finding)
            elif response.status_code != 403:
                from core.engine import Finding
                finding = Finding(
                    technique="WebSocket (Weak Origin Validation)",
                    url=url, severity='MEDIUM', confidence=0.5,
                    param='Origin', payload='https://evil.example.com',
                    evidence=f"WebSocket endpoint did not reject foreign origin (status: {response.status_code})",
                )
                self.engine.add_finding(finding)
        except Exception:
            pass
    
    def _test_ws_injection(self, url):
        """Test for injection via WebSocket upgrade requests"""
        injection_payloads = [
            ("' OR '1'='1", "sqli"),
            ("<script>alert(1)</script>", "xss"),
            ("{{7*7}}", "ssti"),
            ('{"$gt": ""}', "nosqli"),
        ]
        
        for payload, vuln_type in injection_payloads:
            try:
                response = self.requester.request(url, 'GET', headers={
                    'Upgrade': 'websocket',
                    'Connection': 'Upgrade',
                    'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                    'Sec-WebSocket-Version': '13',
                    'Sec-WebSocket-Protocol': payload,
                })
                if not response:
                    continue
                response_text = response.text.lower()
                if 'error' in response_text or 'sql' in response_text or payload.lower() in response_text:
                    from core.engine import Finding
                    finding = Finding(
                        technique=f"WebSocket (Message Injection - {vuln_type.upper()})",
                        url=url, severity='HIGH', confidence=0.7,
                        param='Sec-WebSocket-Protocol', payload=payload,
                        evidence=f"Injection payload reflected/triggered error in WebSocket handshake",
                    )
                    self.engine.add_finding(finding)
                    return
            except Exception:
                continue
    
    def _test_origin_validation(self, url):
        """Test WebSocket origin validation"""
        evil_origins = [
            'https://evil.example.com',
            'null',
            'https://example.com.evil.com',
            '',
            'https://target.com.evil.com',
            'https://evil-target.com',
            'https://target.com%60evil.com',
            'https://target.com%2540evil.com',
        ]
        
        for origin in evil_origins:
            try:
                headers = {
                    'Upgrade': 'websocket',
                    'Connection': 'Upgrade',
                    'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                    'Sec-WebSocket-Version': '13',
                }
                if origin:
                    headers['Origin'] = origin
                
                response = self.requester.request(url, 'GET', headers=headers)
                if not response:
                    continue
                
                if response.status_code == 101:
                    from core.engine import Finding
                    finding = Finding(
                        technique="WebSocket (Origin Bypass)",
                        url=url, severity='HIGH', confidence=0.75,
                        param='Origin', payload=origin or '(empty)',
                        evidence=f"WebSocket accepted connection with origin: {origin or '(empty)'}",
                    )
                    self.engine.add_finding(finding)
                    return
            except Exception:
                continue
    
    def _test_ws_protocol_abuse(self, url):
        """Test for WebSocket protocol abuse via subprotocol manipulation"""
        abuse_payloads = [
            'graphql-ws',
            'graphql-transport-ws',
            'soap',
            'wamp.2.json',
            'mqtt',
        ]
        for protocol in abuse_payloads:
            try:
                response = self.requester.request(url, 'GET', headers={
                    'Upgrade': 'websocket',
                    'Connection': 'Upgrade',
                    'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                    'Sec-WebSocket-Version': '13',
                    'Sec-WebSocket-Protocol': protocol,
                })
                if not response:
                    continue
                if response.status_code == 101 and protocol.lower() in response.headers.get('Sec-WebSocket-Protocol', '').lower():
                    from core.engine import Finding
                    finding = Finding(
                        technique=f"WebSocket (Protocol Accepted: {protocol})",
                        url=url, severity='LOW', confidence=0.6,
                        param='Sec-WebSocket-Protocol', payload=protocol,
                        evidence=f"Server accepted subprotocol: {protocol}",
                    )
                    self.engine.add_finding(finding)
                    return
            except Exception:
                continue
