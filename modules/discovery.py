#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v8.0 - ULTIMATE EDITION
Target Discovery & Enumeration Module

Performs structured discovery to identify valid attack surfaces before
vulnerability testing. Includes:
  - Path & endpoint discovery
  - robots.txt / sitemap.xml parsing
  - Directory brute-forcing with common paths
  - AI-powered smart endpoint prioritization
"""

import re
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse, parse_qs
from collections import Counter


from config import Colors


# ────────────────────────────────────────────
# Common paths for directory brute-forcing
# ────────────────────────────────────────────
COMMON_PATHS = [
    # Admin / management
    '/admin', '/administrator', '/admin/login', '/cpanel', '/dashboard',
    '/manage', '/manager', '/panel', '/control', '/wp-admin',
    # Login / auth
    '/login', '/signin', '/signup', '/register', '/auth', '/oauth',
    '/logout', '/password', '/forgot-password', '/reset-password',
    '/account', '/profile', '/user', '/users',
    # API endpoints
    '/api', '/api/v1', '/api/v2', '/api/v3', '/graphql', '/graphiql',
    '/rest', '/swagger', '/swagger-ui', '/api-docs', '/openapi.json',
    '/api/docs', '/api/schema',
    # Configuration / debug
    '/config', '/configuration', '/settings', '/env', '/.env',
    '/debug', '/trace', '/status', '/health', '/healthcheck',
    '/info', '/server-info', '/server-status', '/phpinfo.php',
    # Backup / development
    '/backup', '/backups', '/bak', '/old', '/temp', '/tmp',
    '/test', '/testing', '/dev', '/development', '/staging',
    '/.git', '/.git/config', '/.svn', '/.hg',
    '/.DS_Store', '/web.config', '/.htaccess',
    # Common CMS / framework paths
    '/wp-login.php', '/wp-content', '/wp-includes', '/wp-json',
    '/xmlrpc.php', '/wp-cron.php',
    '/joomla', '/drupal', '/magento',
    '/vendor', '/node_modules', '/composer.json', '/package.json',
    # File / media / uploads
    '/uploads', '/upload', '/files', '/media', '/static',
    '/assets', '/images', '/img', '/css', '/js',
    '/public', '/private', '/storage', '/data',
    # Error / fallback
    '/404', '/500', '/error', '/errors',
    # Database / cache
    '/phpmyadmin', '/adminer', '/redis', '/memcached',
    '/elasticsearch', '/solr', '/kibana',
    # Robots / sitemap
    '/robots.txt', '/sitemap.xml', '/sitemap_index.xml',
    '/crossdomain.xml', '/security.txt', '/.well-known/security.txt',
    '/humans.txt', '/ads.txt',
]


class DiscoveryModule:
    """Target Discovery & Enumeration Module"""

    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.name = "Target Discovery"

        # Discovered assets
        self.endpoints = set()
        self.directories = set()
        self.file_paths = set()
        self.robots_paths = {'allowed': set(), 'disallowed': set()}
        self.sitemap_urls = set()
        self.technologies = []
        self.interesting_findings = []

    # ──────────────────────────────────────
    # Public API
    # ──────────────────────────────────────

    def run(self, target: str, crawler=None):
        """Run full discovery pipeline on *target*.

        Parameters
        ----------
        target : str
            The root URL to enumerate (e.g. ``https://example.com``).
        crawler : Crawler | None
            An already-executed crawler instance. When provided, its
            results (visited URLs, forms, parameters, resources) are
            merged into the discovery results so we don't crawl twice.
        """
        print(f"\n{Colors.BOLD}{'─'*60}{Colors.RESET}")
        print(f"{Colors.CYAN}  Target Discovery & Enumeration{Colors.RESET}")
        print(f"{Colors.BOLD}{'─'*60}{Colors.RESET}\n")

        base = urlparse(target)
        base_url = f"{base.scheme}://{base.netloc}"

        # 1. Parse robots.txt
        self._parse_robots(base_url)

        # 2. Parse sitemap.xml
        self._parse_sitemap(base_url)

        # 3. Merge crawler results if available
        if crawler is not None:
            self._merge_crawler(crawler, target)

        # 4. Directory brute-force
        modules_cfg = self.engine.config.get('modules', {})
        if modules_cfg.get('dir_brute', False):
            self._dir_brute(base_url)

        # 5. AI-powered smart analysis
        self._smart_analysis(target)

        # 6. Print structured report
        self._print_report(target)

    # ──────────────────────────────────────
    # robots.txt
    # ──────────────────────────────────────

    def _parse_robots(self, base_url: str):
        """Fetch and parse robots.txt for hidden or interesting paths."""
        robots_url = f"{base_url}/robots.txt"
        print(f"{Colors.info(f'Fetching {robots_url}...')}")

        try:
            resp = self.requester.request(robots_url, 'GET')
            if resp and resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            self.robots_paths['disallowed'].add(path)
                            self.endpoints.add(urljoin(base_url, path))
                    elif line.lower().startswith('allow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            self.robots_paths['allowed'].add(path)
                            self.endpoints.add(urljoin(base_url, path))
                    elif line.lower().startswith('sitemap:'):
                        sitemap_url = line.split(':', 1)[1].strip()
                        # Re-attach scheme when the value looked like "//host/path"
                        if sitemap_url.startswith('//'):
                            sitemap_url = urlparse(base_url).scheme + ':' + sitemap_url
                        self._parse_sitemap_url(sitemap_url)

                total = len(self.robots_paths['disallowed']) + len(self.robots_paths['allowed'])
                print(f"{Colors.success(f'robots.txt: {total} paths discovered')}")
            else:
                print(f"{Colors.info('robots.txt not found or inaccessible')}")
        except Exception as e:
            if self.engine.config.get('verbose'):
                print(f"{Colors.error(f'robots.txt error: {e}')}")

    # ──────────────────────────────────────
    # sitemap.xml
    # ──────────────────────────────────────

    def _parse_sitemap(self, base_url: str):
        """Fetch and parse sitemap.xml to discover all listed URLs."""
        sitemap_url = f"{base_url}/sitemap.xml"
        self._parse_sitemap_url(sitemap_url)

    def _parse_sitemap_url(self, sitemap_url: str):
        """Fetch a specific sitemap URL and extract entries."""
        print(f"{Colors.info(f'Fetching {sitemap_url}...')}")
        try:
            resp = self.requester.request(sitemap_url, 'GET')
            if resp and resp.status_code == 200 and resp.text.strip():
                try:
                    root = ET.fromstring(resp.text)
                except ET.ParseError:
                    if self.engine.config.get('verbose'):
                        print(f"{Colors.warning('Sitemap XML parse failed')}")
                    return

                # Handle sitemap index (contains <sitemap><loc>...</loc></sitemap>)
                ns = {'sm': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
                for sitemap_tag in root.findall('.//sm:sitemap/sm:loc', ns):
                    if sitemap_tag.text:
                        self._parse_sitemap_url(sitemap_tag.text.strip())

                # Handle url entries
                for url_tag in root.findall('.//sm:url/sm:loc', ns):
                    if url_tag.text:
                        loc = url_tag.text.strip()
                        self.sitemap_urls.add(loc)
                        self.endpoints.add(loc)

                # Try without namespace (some sitemaps lack it)
                if not self.sitemap_urls:
                    for loc_tag in root.iter('loc'):
                        if loc_tag.text:
                            loc = loc_tag.text.strip()
                            self.sitemap_urls.add(loc)
                            self.endpoints.add(loc)

                if self.sitemap_urls:
                    print(f"{Colors.success(f'sitemap.xml: {len(self.sitemap_urls)} URLs discovered')}")
                else:
                    print(f"{Colors.info('sitemap.xml: no URLs found')}")
            else:
                print(f"{Colors.info('sitemap.xml not found or inaccessible')}")
        except Exception as e:
            if self.engine.config.get('verbose'):
                print(f"{Colors.error(f'sitemap.xml error: {e}')}")

    # ──────────────────────────────────────
    # Directory brute-force
    # ──────────────────────────────────────

    def _dir_brute(self, base_url: str):
        """Probe common paths to discover hidden endpoints."""
        print(f"{Colors.info(f'Directory brute-force ({len(COMMON_PATHS)} paths)...')}")
        found = 0

        for path in COMMON_PATHS:
            full_url = urljoin(base_url, path)

            # Skip if already discovered
            if full_url in self.endpoints:
                continue

            try:
                resp = self.requester.request(full_url, 'GET')
                if resp and resp.status_code not in (404, 500, 502, 503, 0):
                    self.endpoints.add(full_url)
                    self.directories.add(path)
                    found += 1

                    if self.engine.config.get('verbose'):
                        print(f"  {Colors.GREEN}[{resp.status_code}]{Colors.RESET} {path}")
            except Exception:
                pass

        print(f"{Colors.success(f'Directory brute-force: {found} live paths found')}")

    # ──────────────────────────────────────
    # Merge results from an existing Crawler
    # ──────────────────────────────────────

    def _merge_crawler(self, crawler, target: str):
        """Incorporate already-crawled data into the discovery results."""
        for url in crawler.visited:
            self.endpoints.add(url)

        for form in crawler.forms:
            self.endpoints.add(form.get('url', ''))

        # Resource references
        for category, items in crawler.resources.items():
            if category == 'comments':
                for entry in items:
                    self.interesting_findings.append(
                        f"HTML comment on {entry['url']}: {entry['comment'][:120]}"
                    )
            else:
                for item in items:
                    self.endpoints.add(item)

        print(f"{Colors.info(f'Merged {len(crawler.visited)} crawled URLs into discovery results')}")

    # ──────────────────────────────────────
    # AI-powered smart analysis
    # ──────────────────────────────────────

    def _smart_analysis(self, target: str):
        """Heuristic-based smart analysis that categorizes and prioritizes
        discovered endpoints.  This acts as a lightweight "AI" layer that
        scores endpoints by their likely security impact so the tester can
        focus on high-value targets first.
        """
        print(f"{Colors.info('Running smart endpoint analysis...')}")

        # Define high-interest keyword groups and associated weights.
        high_interest = {
            'auth':   ('/login', '/signin', '/auth', '/oauth', '/token',
                        '/session', '/sso', '/password', '/reset',
                        '/forgot', '/register', '/signup'),
            'admin':  ('/admin', '/dashboard', '/manage', '/panel',
                        '/control', '/cpanel', '/wp-admin', '/console'),
            'api':    ('/api', '/graphql', '/rest', '/swagger', '/openapi',
                        '/v1/', '/v2/', '/v3/', '/api-docs'),
            'upload': ('/upload', '/file', '/media', '/attach',
                        '/import', '/export'),
            'config': ('/config', '/.env', '/settings', '/debug',
                        '/phpinfo', '/server-info', '/server-status',
                        '/trace', '/actuator', '/health'),
            'data':   ('/backup', '/dump', '/database', '/db',
                        '/phpmyadmin', '/adminer', '/sql'),
            'scm':    ('/.git', '/.svn', '/.hg', '/.DS_Store',
                        '/web.config', '/.htaccess'),
        }

        category_counts = Counter()
        priority_endpoints = []

        for ep in self.endpoints:
            path = urlparse(ep).path.lower()
            for category, keywords in high_interest.items():
                if any(kw in path for kw in keywords):
                    category_counts[category] += 1
                    priority_endpoints.append((category, ep))
                    break

        # De-duplicate priority list
        seen = set()
        unique_priority = []
        for cat, ep in priority_endpoints:
            if ep not in seen:
                seen.add(ep)
                unique_priority.append((cat, ep))
        priority_endpoints = unique_priority

        # Derive an overall risk suggestion
        risk_level = 'LOW'
        if category_counts.get('config') or category_counts.get('scm'):
            risk_level = 'CRITICAL'
        elif category_counts.get('admin') or category_counts.get('data'):
            risk_level = 'HIGH'
        elif category_counts.get('api') or category_counts.get('auth'):
            risk_level = 'MEDIUM'

        self._analysis_result = {
            'category_counts': dict(category_counts),
            'priority_endpoints': priority_endpoints,
            'risk_level': risk_level,
        }

    # ──────────────────────────────────────
    # Reporting
    # ──────────────────────────────────────

    def _print_report(self, target: str):
        """Print a structured discovery report."""
        print(f"\n{Colors.BOLD}{'─'*60}{Colors.RESET}")
        print(f"{Colors.CYAN}  Discovery Report for {target}{Colors.RESET}")
        print(f"{Colors.BOLD}{'─'*60}{Colors.RESET}")

        # Summary
        print(f"\n  {Colors.BOLD}Summary{Colors.RESET}")
        print(f"    Total endpoints discovered  : {len(self.endpoints)}")
        print(f"    Sitemap URLs                : {len(self.sitemap_urls)}")
        print(f"    robots.txt allowed paths     : {len(self.robots_paths['allowed'])}")
        print(f"    robots.txt disallowed paths  : {len(self.robots_paths['disallowed'])}")
        print(f"    Live directories             : {len(self.directories)}")

        # Robots
        if self.robots_paths['disallowed']:
            print(f"\n  {Colors.BOLD}robots.txt – Disallowed Paths (potential hidden content){Colors.RESET}")
            for path in sorted(self.robots_paths['disallowed']):
                print(f"    {Colors.YELLOW}{path}{Colors.RESET}")

        # Smart analysis
        analysis = getattr(self, '_analysis_result', None)
        if analysis:
            risk = analysis['risk_level']
            risk_color = {
                'CRITICAL': f"{Colors.RED}{Colors.BOLD}",
                'HIGH':     Colors.RED,
                'MEDIUM':   Colors.YELLOW,
                'LOW':      Colors.GREEN,
            }.get(risk, Colors.WHITE)

            print(f"\n  {Colors.BOLD}Smart Analysis{Colors.RESET}")
            print(f"    Estimated attack surface risk: {risk_color}{risk}{Colors.RESET}")

            if analysis['category_counts']:
                print(f"\n    {Colors.BOLD}Endpoint Categories:{Colors.RESET}")
                for cat, count in sorted(analysis['category_counts'].items(),
                                         key=lambda x: -x[1]):
                    print(f"      {cat:10s} : {count}")

            if analysis['priority_endpoints']:
                print(f"\n    {Colors.BOLD}High-Priority Endpoints:{Colors.RESET}")
                for cat, ep in analysis['priority_endpoints'][:20]:
                    print(f"      [{cat:6s}] {ep}")

        # Interesting findings (e.g. HTML comments)
        if self.interesting_findings:
            print(f"\n  {Colors.BOLD}Interesting Findings{Colors.RESET}")
            for finding in self.interesting_findings[:15]:
                print(f"    {Colors.YELLOW}{finding}{Colors.RESET}")

        print(f"\n{Colors.BOLD}{'─'*60}{Colors.RESET}")
