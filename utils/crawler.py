#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Web Crawler Module
"""

import os
import sys
import re
from urllib.parse import urljoin, urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Colors


class Crawler:
    """Web Crawler"""
    
    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.visited = set()
        self.forms = []
        self.parameters = []
    
    def crawl(self, start_url: str, depth: int = 3):
        """Crawl website"""
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            print(f"{Colors.error('BeautifulSoup not installed. Crawling limited.')}")
            return set(), [], []
        
        to_visit = [(start_url, 0)]
        base_domain = urlparse(start_url).netloc
        
        while to_visit:
            url, current_depth = to_visit.pop(0)
            
            if url in self.visited or current_depth > depth:
                continue
            
            self.visited.add(url)
            
            try:
                response = self.requester.request(url, 'GET')
                
                if not response:
                    continue
                
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract forms
                self._extract_forms(soup, url)
                
                # Extract URL parameters
                self._extract_parameters(url)
                
                # Extract links
                if current_depth < depth:
                    for link in soup.find_all('a', href=True):
                        full_url = urljoin(url, link['href'])
                        
                        # Stay on same domain
                        if urlparse(full_url).netloc == base_domain:
                            if full_url not in self.visited:
                                to_visit.append((full_url, current_depth + 1))
                
                # Extract API endpoints from scripts
                self._extract_api_endpoints(soup, url)
                
            except Exception as e:
                if self.engine.config.get('verbose'):
                    print(f"{Colors.error(f'Crawl error: {e}')}")
        
        return self.visited, self.forms, self.parameters
    
    def _extract_forms(self, soup, url: str):
        """Extract forms from page"""
        for form in soup.find_all('form'):
            action = form.get('action', '')
            form_url = urljoin(url, action) if action else url
            method = form.get('method', 'get').lower()
            
            inputs = []
            for inp in form.find_all(['input', 'textarea', 'select']):
                name = inp.get('name')
                if name:
                    inputs.append({
                        'name': name,
                        'type': inp.get('type', 'text'),
                        'value': inp.get('value', ''),
                    })
            
            self.forms.append({
                'url': form_url,
                'method': method,
                'inputs': inputs,
            })
            
            # Add to parameters
            for inp in inputs:
                self.parameters.append((form_url, method, inp['name'], inp.get('value', ''), 'form'))
    
    def _extract_parameters(self, url: str):
        """Extract URL parameters"""
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for name, values in params.items():
                for value in values:
                    self.parameters.append((url, 'get', name, value, 'url_param'))
    
    def _extract_api_endpoints(self, soup, url: str):
        """Extract API endpoints from JavaScript"""
        for script in soup.find_all('script'):
            if script.string:
                # Find API patterns
                patterns = [
                    r'["\'](/api/[^"\']+)["\']',
                    r'["\'](/v\d+/[^"\']+)["\']',
                    r'["\'](https?://[^"\']+/api/[^"\']+)["\']',
                ]
                
                for pattern in patterns:
                    matches = re.findall(pattern, script.string)
                    for match in matches:
                        api_url = urljoin(url, match)
                        self.parameters.append((api_url, 'get', '', '', 'api'))
