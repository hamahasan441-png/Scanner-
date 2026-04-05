#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v9.0 - ULTIMATE EDITION
Advanced Web Crawler Module
"""

import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse


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
        
        max_urls = 2000  # Prevent excessive crawling
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

            if len(self.visited) % 100 == 0 and self.engine.config.get('verbose'):
                print(f"{Colors.info(f'Crawl progress: {len(self.visited)} URLs visited')}")

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

                # Extract additional links from <link>, <base>, <area>, data-* attrs
                self._extract_link_params(soup, url, base_domain, to_visit, current_depth, depth)

                # Extract parameter names from JavaScript
                self._extract_js_params(soup, url)

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
        """Extract URL parameters.

        Stores the full URL (including query string) for each parameter.
        The requester handles stripping the tested parameter before sending
        to avoid duplicate query-string keys.
        """
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            for name, values in params.items():
                for value in values:
                    self.parameters.append((url, 'get', name, value, 'url_param'))

        # Extract path parameters (numeric/UUID segments that are likely IDs)
        self._extract_path_params(url)

    # Patterns that identify path segments likely to be injectable IDs
    _PATH_ID_RE = re.compile(r'^\d+$')
    _PATH_UUID_RE = re.compile(r'^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$', re.I)
    _PATH_HEX_HASH_RE = re.compile(r'^[0-9a-f]{32,64}$', re.I)
    _PATH_SLUG_ID_RE = re.compile(r'^\d+-[\w-]+$')
    _PATH_BASE64_RE = re.compile(r'^[A-Za-z0-9+/=]{16,}$')
    _PATH_SHORT_TOKEN_RE = re.compile(r'^[a-zA-Z0-9]{8,12}$')

    def _extract_path_params(self, url: str):
        """Extract injectable path segments as testable parameters.

        Detects numeric IDs, UUIDs, hex hashes, slugified IDs, Base64
        segments, and short alphanumeric tokens.
        Example: /users/42/profile → param 'path[1]' with value '42'
        """
        parsed = urlparse(url)
        segments = [s for s in parsed.path.split('/') if s]
        path_patterns = (
            self._PATH_ID_RE,
            self._PATH_UUID_RE,
            self._PATH_HEX_HASH_RE,
            self._PATH_SLUG_ID_RE,
            self._PATH_BASE64_RE,
            self._PATH_SHORT_TOKEN_RE,
        )
        for idx, seg in enumerate(segments):
            if any(p.match(seg) for p in path_patterns):
                self.parameters.append((url, 'get', f'path[{idx}]', seg, 'path_param'))
    
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
                    # GraphQL endpoints
                    r'["\'](/graphql[^"\']*)["\']',
                    # REST versioned APIs
                    r'["\'](/rest/[^"\']+)["\']',
                    # WebSocket URLs
                    r'["\'](wss?://[^"\']+)["\']',
                    # Template literals with interpolation
                    r'`([^`]*\$\{[^`]*\}[^`]*)`',
                    # window.location / document.location assignments
                    r'(?:window|document)\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']',
                    # HTTP method calls on any object (.get/.post/.put/.delete)
                    r'\.\s*(?:get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']',
                ]
                
                for pattern in patterns:
                    matches = re.findall(pattern, script.string)
                    for match in matches:
                        endpoint = match[-1] if isinstance(match, tuple) else match
                        api_url = urljoin(url, endpoint)
                        # Extract query params from API URLs so they are
                        # individually testable (e.g., /api/items?id=1).
                        api_parsed = urlparse(api_url)
                        if api_parsed.query:
                            api_params = parse_qs(api_parsed.query, keep_blank_values=True)
                            for p_name, p_vals in api_params.items():
                                for p_val in p_vals:
                                    self.parameters.append((api_url, 'get', p_name, p_val, 'api_extracted'))
                        else:
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

    def _extract_js_params(self, soup, url: str):
        """Extract parameter names from JavaScript source.

        Looks for URLSearchParams usage, FormData appends, object keys in
        request bodies, and getElementById/getElementsByName form value
        extractions.
        """
        for script in soup.find_all('script'):
            if not script.string:
                continue
            src = script.string

            # URLSearchParams .get/.set/.append/.has
            for match in re.findall(r'\.(?:get|set|append|has)\(["\'](\w+)["\']\)', src):
                self.parameters.append((url, 'get', match, '', 'js_param'))

            # FormData .append('name', ...)
            for match in re.findall(r'\.append\(["\'](\w+)["\']\s*,', src):
                self.parameters.append((url, 'post', match, '', 'js_formdata'))

            # Object keys in body/data/params: { key: ... }
            body_blocks = re.findall(r'(?:body|data|params)\s*[:=]\s*\{([^}]+)\}', src)
            for block in body_blocks:
                for key in re.findall(r'["\']?(\w+)["\']?\s*:', block):
                    if key not in ('true', 'false', 'null', 'undefined'):
                        self.parameters.append((url, 'post', key, '', 'js_body_key'))

            # getElementById / getElementsByName form value extraction
            for match in re.findall(r'getElement(?:ById|sByName)\(["\'](\w+)["\']\)', src):
                self.parameters.append((url, 'get', match, '', 'js_dom_param'))

    def _extract_link_params(self, soup, url: str, base_domain: str,
                             to_visit: list, current_depth: int, max_depth: int):
        """Extract additional navigable links from the page.

        Covers <link> canonical/alternate, <base> href, <area> href,
        and data-href / data-src / data-action attributes on any element.
        Discovered same-domain URLs are added to the crawl queue.
        """
        found_urls = set()

        # <link rel="canonical|alternate"> tags
        for link in soup.find_all('link', href=True):
            rel = ' '.join(link.get('rel', []))
            if any(r in rel for r in ('canonical', 'alternate')):
                found_urls.add(urljoin(url, link['href']))

        # <base> href
        base_tag = soup.find('base', href=True)
        if base_tag:
            found_urls.add(urljoin(url, base_tag['href']))

        # <area> href
        for area in soup.find_all('area', href=True):
            found_urls.add(urljoin(url, area['href']))

        # data-href, data-src, data-action on any element
        for attr in ('data-href', 'data-src', 'data-action'):
            for elem in soup.find_all(attrs={attr: True}):
                val = elem.get(attr, '')
                if val:
                    found_urls.add(urljoin(url, val))

        # Enqueue same-domain links for crawling
        for found in found_urls:
            if urlparse(found).netloc == base_domain:
                self.parameters.append((found, 'get', '', '', 'link_extracted'))
                if current_depth < max_depth and found not in self.visited:
                    to_visit.append((found, current_depth + 1))

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
