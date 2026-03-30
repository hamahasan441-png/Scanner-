#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Reconnaissance Module
"""

import os
import sys
import re
import socket
import subprocess
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Colors


class ReconModule:
    """Reconnaissance Module"""
    
    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
    
    def run(self, target: str):
        """Run reconnaissance"""
        print(f"{Colors.info('Running reconnaissance...')}")
        
        domain = urlparse(target).netloc
        
        # DNS lookup
        self._dns_lookup(domain)
        
        # Technology detection
        self._detect_tech(target)
        
        # WHOIS lookup
        self._whois_lookup(domain)
    
    def _dns_lookup(self, domain: str):
        """DNS enumeration"""
        try:
            ip = socket.gethostbyname(domain)
            print(f"{Colors.info(f'DNS: {domain} -> {ip}')}")
            
            # Reverse DNS
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                print(f"{Colors.info(f'Reverse DNS: {hostname}')}")
            except:
                pass
            
            # MX records (simplified)
            try:
                import dns.resolver
                mx_records = dns.resolver.resolve(domain, 'MX')
                for mx in mx_records:
                    print(f"{Colors.info(f'MX: {mx.exchange}')}")
            except:
                pass
                
        except Exception as e:
            if self.engine.config.get('verbose'):
                print(f"{Colors.error(f'DNS lookup error: {e}')}")
    
    def _detect_tech(self, url: str):
        """Detect technologies"""
        try:
            response = self.requester.request(url, 'GET')
            
            if not response:
                return
            
            tech = []
            headers = response.headers
            
            # Server header
            if 'Server' in headers:
                tech.append(f"Server: {headers['Server']}")
            
            # X-Powered-By
            if 'X-Powered-By' in headers:
                tech.append(f"Powered by: {headers['X-Powered-By']}")
            
            # Cookies
            if 'Set-Cookie' in headers:
                cookies = headers['Set-Cookie']
                if 'PHPSESSID' in cookies:
                    tech.append('PHP')
                if 'ASP.NET_SessionId' in cookies:
                    tech.append('ASP.NET')
                if 'JSESSIONID' in cookies:
                    tech.append('Java')
            
            # Body analysis
            body = response.text[:5000]
            
            frameworks = {
                'WordPress': r'/wp-content|wp-includes',
                'Drupal': r'Drupal|drupal',
                'Joomla': r'Joomla|joomla',
                'React': r'react|reactjs',
                'Angular': r'angular|ng-',
                'Vue.js': r'vue\.js|vuejs',
                'jQuery': r'jquery',
                'Bootstrap': r'bootstrap',
                'Laravel': r'laravel',
                'Django': r'django|csrfmiddlewaretoken',
                'Flask': r'flask',
                'Express.js': r'express',
                'Ruby on Rails': r'rails',
                'Spring': r'spring',
            }
            
            for fw, pattern in frameworks.items():
                if re.search(pattern, body, re.IGNORECASE):
                    tech.append(fw)
            
            if tech:
                print(f"{Colors.info('Technologies detected:')}")
                for t in tech:
                    print(f"  - {t}")
                    
        except Exception as e:
            if self.engine.config.get('verbose'):
                print(f"{Colors.error(f'Tech detection error: {e}')}")
    
    def _whois_lookup(self, domain: str):
        """WHOIS lookup"""
        try:
            result = subprocess.run(
                ['whois', domain],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                # Extract key info
                lines = result.stdout.split('\n')
                for line in lines[:20]:
                    if ':' in line and not line.startswith('%'):
                        print(f"  {line.strip()}")
                        
        except Exception as e:
            if self.engine.config.get('verbose'):
                print(f"{Colors.error(f'WHOIS error: {e}')}")
