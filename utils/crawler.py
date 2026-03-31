#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v8.0 - ULTIMATE EDITION
Advanced Web Crawler Module
"""

import re
from urllib.parse import urljoin, urlparse, parse_qs


from config import Colors


class Crawler:
    """Web Crawler with endpoint graph tracking"""
    
    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.visited = set()
        self.forms = []
        self.parameters = []
        self.resources = {
            'scripts': set(),
            'stylesheets': set(),
            'images': set(),
            'iframes': set(),
            'media': set(),
            'comments': [],
        }
        # Graph representation: tracks relationships between endpoints
        self.endpoint_graph = {}  # url → {methods, params, auth_state, related}
        self.auth_indicators = set()  # URLs that appear to require authentication
    
    def crawl(self, start_url: str, depth: int = 3):
        """Crawl website"""
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            print(f"{Colors.error('BeautifulSoup not installed. Crawling limited.')}")
            return set(), [], []
        
        max_urls = 500  # Prevent excessive crawling
        to_visit = [(start_url, 0)]
        base_domain = urlparse(start_url).netloc
        
        while to_visit:
            if len(self.visited) >= max_urls:
                if self.engine.config.get('verbose'):
                    print(f"{Colors.warning(f'Crawl limit reached ({max_urls} URLs)')}")
                break
            
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
                
                # Extract links and resource references
                if current_depth < depth:
                    for link in soup.find_all('a', href=True):
                        full_url = urljoin(url, link['href'])
                        
                        # Stay on same domain
                        if urlparse(full_url).netloc == base_domain:
                            if full_url not in self.visited:
                                to_visit.append((full_url, current_depth + 1))
                
                # Extract referenced resources (scripts, stylesheets, images, etc.)
                self._extract_resources(soup, url)
                
                # Extract API endpoints from scripts
                self._extract_api_endpoints(soup, url)
                
                # Extract hidden parameters
                self._extract_hidden_params(soup, url)
                
                # Extract HTML comments (may contain debug info or paths)
                self._extract_comments(soup, url)

                # Build graph entry for this URL
                self._update_graph(url, response, soup)
                
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
    
    def _extract_resources(self, soup, url: str):
        """Extract referenced resources: scripts, stylesheets, images, iframes, media"""
        base_domain = urlparse(url).netloc

        # Script sources
        for script in soup.find_all('script', src=True):
            src = urljoin(url, script['src'])
            self.resources['scripts'].add(src)

        # Stylesheet links
        for link in soup.find_all('link', href=True):
            href = urljoin(url, link['href'])
            rel = ' '.join(link.get('rel', []))
            if 'stylesheet' in rel:
                self.resources['stylesheets'].add(href)

        # Images
        for img in soup.find_all('img', src=True):
            self.resources['images'].add(urljoin(url, img['src']))

        # Iframes
        for iframe in soup.find_all('iframe', src=True):
            self.resources['iframes'].add(urljoin(url, iframe['src']))

        # Video / audio / source elements
        for tag in soup.find_all(['video', 'audio', 'source'], src=True):
            self.resources['media'].add(urljoin(url, tag['src']))

    def _extract_api_endpoints(self, soup, url: str):
        """Extract API endpoints from JavaScript"""
        for script in soup.find_all('script'):
            if script.string:
                # Find API patterns
                patterns = [
                    r'["\'](/api/[^"\']+)["\']',
                    r'["\'](/v\d+/[^"\']+)["\']',
                    r'["\'](https?://[^"\']+/api/[^"\']+)["\']',
                    r'fetch\(["\']([^"\']+)["\']',
                    r'\.ajax\(\{[^}]*url:\s*["\']([^"\']+)["\']',
                    r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']',
                    r'XMLHttpRequest[^}]*\.open\(["\'](?:GET|POST|PUT|DELETE)["\']\s*,\s*["\']([^"\']+)["\']',
                ]
                
                for pattern in patterns:
                    matches = re.findall(pattern, script.string)
                    for match in matches:
                        endpoint = match[-1] if isinstance(match, tuple) else match
                        api_url = urljoin(url, endpoint)
                        self.parameters.append((api_url, 'get', '', '', 'api'))
                
                # Extract JSON keys as potential hidden parameters
                json_patterns = [
                    r'["\'](\w+)["\']\s*:\s*["\']',
                    r'data\.\s*(\w+)',
                    r'params\.\s*(\w+)',
                ]
                for pattern in json_patterns:
                    matches = re.findall(pattern, script.string)
                    for param_name in matches:
                        if len(param_name) > 1 and param_name not in ('true', 'false', 'null', 'undefined'):
                            self.parameters.append((url, 'get', param_name, '', 'js_extracted'))
    
    def _extract_hidden_params(self, soup, url: str):
        """Extract hidden input fields and meta parameters"""
        # Hidden inputs
        for inp in soup.find_all('input', {'type': 'hidden'}):
            name = inp.get('name')
            if name:
                self.parameters.append((url, 'get', name, inp.get('value', ''), 'hidden_input'))
        
        # Data attributes
        for elem in soup.find_all(attrs={'data-url': True}):
            data_url = urljoin(url, elem.get('data-url', ''))
            self.parameters.append((data_url, 'get', '', '', 'data_attr'))
        
        # Meta tags with URLs
        for meta in soup.find_all('meta', content=True):
            content = meta.get('content', '')
            if content.startswith(('http://', 'https://', '/')):
                meta_url = urljoin(url, content)
                self.parameters.append((meta_url, 'get', '', '', 'meta'))

    def _extract_comments(self, soup, url: str):
        """Extract HTML comments that may reveal paths, debug info, or credentials"""
        from bs4 import Comment
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        for comment in comments:
            text = comment.strip()
            if text:
                self.resources['comments'].append({'url': url, 'comment': text})

    # ------------------------------------------------------------------
    # Endpoint graph (§2 of the pipeline)
    # ------------------------------------------------------------------

    def _update_graph(self, url, response, soup):
        """Build or update the graph entry for a crawled URL.

        Tracks: methods, input parameters, authentication state, and
        related endpoints discovered from this page.
        """
        parsed = urlparse(url)
        path = parsed.path or '/'

        if path not in self.endpoint_graph:
            self.endpoint_graph[path] = {
                'url': url,
                'methods': set(),
                'params': set(),
                'auth_state': 'unknown',
                'related': set(),
            }

        entry = self.endpoint_graph[path]
        entry['methods'].add('GET')

        # Track parameters from URL query
        if parsed.query:
            for name in parse_qs(parsed.query):
                entry['params'].add(name)

        # Track form parameters and their methods
        for form in soup.find_all('form'):
            method = form.get('method', 'get').upper()
            entry['methods'].add(method)
            for inp in form.find_all(['input', 'textarea', 'select']):
                name = inp.get('name')
                if name:
                    entry['params'].add(name)

        # Detect authentication state from response
        if response:
            auth_hints = ['login', 'signin', 'auth', 'session', 'token']
            path_lower = path.lower()
            headers_lower = str(response.headers).lower()

            if any(h in path_lower for h in auth_hints):
                entry['auth_state'] = 'auth_endpoint'
                self.auth_indicators.add(url)
            elif 'set-cookie' in headers_lower:
                entry['auth_state'] = 'sets_cookie'
            elif response.status_code in (401, 403):
                entry['auth_state'] = 'requires_auth'
                self.auth_indicators.add(url)

        # Track related links from this page
        for link in soup.find_all('a', href=True):
            href = urljoin(url, link['href'])
            href_path = urlparse(href).path or '/'
            if href_path != path:
                entry['related'].add(href_path)

    def get_graph_summary(self):
        """Return a plain-text summary of the endpoint graph.

        Format: User → /login → token → /api/user → /admin
        """
        lines = []
        for path, data in self.endpoint_graph.items():
            methods = ','.join(sorted(data['methods']))
            params = ','.join(sorted(data['params'])) if data['params'] else 'none'
            related = ' → '.join(sorted(data['related'])[:5]) if data['related'] else 'none'
            lines.append(
                f"  [{methods}] {path} (params: {params}, auth: {data['auth_state']}) → {related}"
            )
        return '\n'.join(lines)
