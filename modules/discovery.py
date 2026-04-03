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
import asyncio
import subprocess
import json
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse, parse_qs, quote
from urllib.request import urlopen, Request
from collections import Counter

try:
    import aiohttp
    _HAS_AIOHTTP = True
except ImportError:
    _HAS_AIOHTTP = False

try:
    from bs4 import BeautifulSoup
    _HAS_BS4 = True
except ImportError:
    _HAS_BS4 = False


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


# ── Custom-404 detection thresholds ──────────────────────────────────────
_CUSTOM_404_LENGTH_THRESHOLD = 50       # max byte-length diff from canary
_CUSTOM_404_SIMILARITY_THRESHOLD = 0.9  # min word-overlap ratio to consider same


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

        # 6. Async web crawling for deeper endpoint discovery
        async_urls = self._async_crawl([target], depth=2)
        if async_urls:
            self.endpoints.update(async_urls)

        # 7. Enhanced link extraction from already-discovered pages
        self._enhanced_link_extraction(target)

        # 8. JavaScript rendering discovery for SPA pages
        self._js_render_discovery(target)

        # 9. Passive URL collection from web archives
        self._passive_url_collection(target)

        # 10. Print structured report
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
        """Probe common paths to discover hidden endpoints.

        Uses a baseline 404 fingerprint to avoid false positives from
        custom error pages that return HTTP 200.
        """
        print(f"{Colors.info(f'Directory brute-force ({len(COMMON_PATHS)} paths)...')}")
        found = 0

        # Build a baseline "not found" fingerprint so we can detect
        # custom 404 pages that return 200.
        baseline_len = 0
        baseline_words: set = set()
        try:
            canary_url = urljoin(base_url, '/atomic_nonexistent_path_9f3a1b')
            canary_resp = self.requester.request(canary_url, 'GET')
            if canary_resp:
                baseline_len = len(canary_resp.text)
                baseline_words = set(canary_resp.text.lower().split()[:50])
        except Exception:
            pass

        for path in COMMON_PATHS:
            full_url = urljoin(base_url, path)

            # Skip if already discovered
            if full_url in self.endpoints:
                continue

            try:
                resp = self.requester.request(full_url, 'GET')
                if resp and resp.status_code not in (404, 500, 502, 503, 0):
                    # Custom 404 detection: if response body is very similar
                    # to our canary, treat it as a false positive.
                    if baseline_len > 0 and resp.status_code == 200:
                        body_len = len(resp.text)
                        if abs(body_len - baseline_len) < _CUSTOM_404_LENGTH_THRESHOLD:
                            resp_words = set(resp.text.lower().split()[:50])
                            overlap = len(baseline_words & resp_words)
                            if baseline_words and overlap / len(baseline_words) > _CUSTOM_404_SIMILARITY_THRESHOLD:
                                continue  # likely a custom 404

                    self.endpoints.add(full_url)
                    self.directories.add(path)
                    found += 1

                    if self.engine.config.get('verbose'):
                        print(f"  {Colors.GREEN}[{resp.status_code}]{Colors.RESET} {path}")
            except Exception as e:
                if self.engine.config.get('verbose'):
                    print(f"{Colors.warning(f'  Dir brute error on {path}: {e}')}")

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
    # Async Web Crawling (aiohttp + asyncio)
    # ──────────────────────────────────────

    def _async_crawl(self, seed_urls, depth=2):
        """Crawl seed URLs asynchronously using aiohttp for high-performance
        concurrent HTTP fetching.

        Parameters
        ----------
        seed_urls : list[str]
            Initial URLs to begin crawling from.
        depth : int
            Maximum crawl depth (number of link-follow hops).

        Returns
        -------
        set[str]
            Newly discovered URLs within the same domain scope.
        """
        if not _HAS_AIOHTTP:
            if self.engine.config.get('verbose'):
                print(f"{Colors.info('aiohttp not installed – skipping async crawl')}")
            return set()

        print(f"{Colors.info('Running async web crawl...')}")

        target_domain = urlparse(seed_urls[0]).netloc if seed_urls else ''
        discovered = set()

        async def _fetch(session, url):
            """Fetch a single URL and return its text content."""
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10),
                                       ssl=False) as resp:
                    if resp.status == 200 and 'text' in resp.content_type:
                        return await resp.text(errors='replace')
            except Exception:
                pass
            return ''

        async def _extract_links(html, base_url):
            """Extract same-domain links from HTML using regex."""
            links = set()
            # Match href="..." and src="..."
            for match in re.finditer(r'(?:href|src)\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE):
                link = match.group(1)
                absolute = urljoin(base_url, link)
                parsed = urlparse(absolute)
                if parsed.netloc == target_domain and parsed.scheme in ('http', 'https'):
                    links.add(absolute)
            return links

        async def _crawl():
            visited = set()
            to_visit = set(seed_urls)

            async with aiohttp.ClientSession() as session:
                for _depth_level in range(depth):
                    if not to_visit:
                        break
                    batch = list(to_visit - visited)[:50]
                    if not batch:
                        break

                    tasks = [_fetch(session, url) for url in batch]
                    results = await asyncio.gather(*tasks, return_exceptions=True)

                    next_visit = set()
                    for url, html in zip(batch, results):
                        visited.add(url)
                        if isinstance(html, str) and html:
                            links = await _extract_links(html, url)
                            discovered.update(links)
                            next_visit.update(links - visited)

                    to_visit = next_visit

            return discovered

        try:
            loop = None
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                pass

            if loop and loop.is_running():
                # We're already inside an event loop – run in a new thread
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    future = pool.submit(asyncio.run, _crawl())
                    result = future.result(timeout=60)
            else:
                result = asyncio.run(_crawl())

            new_urls = result - self.endpoints
            if new_urls:
                print(f"{Colors.success(f'Async crawl: {len(new_urls)} new URLs discovered')}")
            else:
                print(f"{Colors.info('Async crawl: no new URLs found')}")
            return result
        except Exception as e:
            if self.engine.config.get('verbose'):
                print(f"{Colors.error(f'Async crawl error: {e}')}")
            return set()

    # ──────────────────────────────────────
    # Enhanced Link Extraction (BeautifulSoup)
    # ──────────────────────────────────────

    def _enhanced_link_extraction(self, target: str):
        """Use BeautifulSoup (with lxml or html.parser fallback) for
        comprehensive link extraction from the target page.

        Extracts links from HTML elements (a, form, script, link, img,
        iframe, area, meta refresh) and inline JavaScript URL patterns
        (window.location, document.location, fetch(), XMLHttpRequest).

        Parameters
        ----------
        target : str
            The root URL to analyse for links.
        """
        if not _HAS_BS4:
            if self.engine.config.get('verbose'):
                print(f"{Colors.info('bs4 not installed – skipping enhanced link extraction')}")
            return

        print(f"{Colors.info('Running enhanced link extraction...')}")

        target_parsed = urlparse(target)
        target_domain = target_parsed.netloc

        try:
            resp = self.requester.request(target, 'GET')
            if not resp or resp.status_code != 200:
                return
        except Exception as e:
            if self.engine.config.get('verbose'):
                print(f"{Colors.error(f'Enhanced extraction fetch error: {e}')}")
            return

        html = resp.text

        # Select parser: prefer lxml, fall back to html.parser
        try:
            soup = BeautifulSoup(html, 'lxml')
        except Exception:
            soup = BeautifulSoup(html, 'html.parser')

        found = set()

        # Tag-attribute pairs to extract URLs from
        tag_attrs = [
            ('a', 'href'),
            ('form', 'action'),
            ('script', 'src'),
            ('link', 'href'),
            ('img', 'src'),
            ('iframe', 'src'),
            ('area', 'href'),
        ]

        for tag_name, attr in tag_attrs:
            for tag in soup.find_all(tag_name):
                value = tag.get(attr)
                if value:
                    absolute = urljoin(target, value)
                    parsed = urlparse(absolute)
                    if parsed.netloc == target_domain and parsed.scheme in ('http', 'https'):
                        found.add(absolute)

        # meta http-equiv="refresh" content="0;url=..."
        for meta in soup.find_all('meta', attrs={'http-equiv': re.compile(r'refresh', re.IGNORECASE)}):
            content = meta.get('content', '')
            match = re.search(r'url\s*=\s*(.+)', content, re.IGNORECASE)
            if match:
                url = match.group(1).strip().strip('\'"')
                absolute = urljoin(target, url)
                parsed = urlparse(absolute)
                if parsed.netloc == target_domain and parsed.scheme in ('http', 'https'):
                    found.add(absolute)

        # Inline JavaScript URL patterns
        js_patterns = [
            r'window\.location\s*[=]\s*["\']([^"\']+)["\']',
            r'document\.location\s*[=]\s*["\']([^"\']+)["\']',
            r'window\.location\.href\s*[=]\s*["\']([^"\']+)["\']',
            r'document\.location\.href\s*[=]\s*["\']([^"\']+)["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'XMLHttpRequest[^"\']*open\s*\(\s*["\'][^"\']*["\']\s*,\s*["\']([^"\']+)["\']',
        ]

        for script in soup.find_all('script'):
            js_text = script.string or ''
            for pattern in js_patterns:
                for match in re.finditer(pattern, js_text):
                    url = match.group(1)
                    absolute = urljoin(target, url)
                    parsed = urlparse(absolute)
                    if parsed.netloc == target_domain and parsed.scheme in ('http', 'https'):
                        found.add(absolute)

        new_urls = found - self.endpoints
        self.endpoints.update(found)
        if new_urls:
            print(f"{Colors.success(f'Enhanced extraction: {len(new_urls)} new URLs found')}")
        else:
            print(f"{Colors.info('Enhanced extraction: no new URLs found')}")

    # ──────────────────────────────────────
    # JavaScript Rendering (Playwright/Selenium)
    # ──────────────────────────────────────

    def _js_render_discovery(self, target: str, timeout: int = 30):
        """Render the target page in a headless browser to discover URLs
        generated dynamically by JavaScript (SPAs, client-side routing).

        Tries Playwright first (``python -m playwright`` or ``node`` with
        Puppeteer), then falls back to Selenium.  All tools are invoked
        via subprocess to avoid hard dependencies.

        Parameters
        ----------
        target : str
            The URL to render.
        timeout : int
            Maximum seconds to wait for the subprocess to complete.
        """
        print(f"{Colors.info('Attempting JS rendering discovery...')}")

        target_domain = urlparse(target).netloc
        rendered_urls = set()

        # ── Helper: extract URLs from raw page source ──
        def _extract_urls_from_source(source: str):
            urls = set()
            for match in re.finditer(r'(?:href|src|action)\s*=\s*["\']([^"\']+)["\']', source, re.IGNORECASE):
                link = match.group(1)
                absolute = urljoin(target, link)
                parsed = urlparse(absolute)
                if parsed.netloc == target_domain and parsed.scheme in ('http', 'https'):
                    urls.add(absolute)
            return urls

        # ── Strategy 1: Playwright via Python ──
        playwright_script = (
            "import sys, json\n"
            "from playwright.sync_api import sync_playwright\n"
            "with sync_playwright() as p:\n"
            "    browser = p.chromium.launch(headless=True)\n"
            "    page = browser.new_page()\n"
            "    page.goto(sys.argv[1], wait_until='networkidle', timeout=20000)\n"
            "    print(page.content())\n"
            "    browser.close()\n"
        )
        try:
            proc = subprocess.run(
                ['python', '-c', playwright_script, target],
                capture_output=True, text=True, timeout=timeout
            )
            if proc.returncode == 0 and proc.stdout.strip():
                rendered_urls = _extract_urls_from_source(proc.stdout)
                new_urls = rendered_urls - self.endpoints
                self.endpoints.update(rendered_urls)
                print(f"{Colors.success(f'JS render (Playwright): {len(new_urls)} new URLs')}")
                return
        except FileNotFoundError:
            pass
        except subprocess.TimeoutExpired:
            if self.engine.config.get('verbose'):
                print(f"{Colors.warning('Playwright timed out')}")
        except Exception as e:
            if self.engine.config.get('verbose'):
                print(f"{Colors.warning(f'Playwright unavailable: {e}')}")

        # ── Strategy 2: Puppeteer via Node.js ──
        puppeteer_script = (
            "const puppeteer = require('puppeteer');"
            "(async () => {"
            "  const browser = await puppeteer.launch({headless: 'new', args: ['--no-sandbox']});"
            "  const page = await browser.newPage();"
            "  await page.goto(process.argv[2], {waitUntil: 'networkidle0', timeout: 20000});"
            "  const html = await page.content();"
            "  console.log(html);"
            "  await browser.close();"
            "})();"
        )
        try:
            proc = subprocess.run(
                ['node', '-e', puppeteer_script, target],
                capture_output=True, text=True, timeout=timeout
            )
            if proc.returncode == 0 and proc.stdout.strip():
                rendered_urls = _extract_urls_from_source(proc.stdout)
                new_urls = rendered_urls - self.endpoints
                self.endpoints.update(rendered_urls)
                print(f"{Colors.success(f'JS render (Puppeteer): {len(new_urls)} new URLs')}")
                return
        except FileNotFoundError:
            pass
        except subprocess.TimeoutExpired:
            if self.engine.config.get('verbose'):
                print(f"{Colors.warning('Puppeteer timed out')}")
        except Exception as e:
            if self.engine.config.get('verbose'):
                print(f"{Colors.warning(f'Puppeteer unavailable: {e}')}")

        # ── Strategy 3: Selenium via Python ──
        selenium_script = (
            "import sys, time\n"
            "from selenium import webdriver\n"
            "from selenium.webdriver.chrome.options import Options\n"
            "opts = Options()\n"
            "opts.add_argument('--headless')\n"
            "opts.add_argument('--no-sandbox')\n"
            "opts.add_argument('--disable-dev-shm-usage')\n"
            "driver = webdriver.Chrome(options=opts)\n"
            "driver.set_page_load_timeout(20)\n"
            "driver.get(sys.argv[1])\n"
            "time.sleep(3)\n"
            "print(driver.page_source)\n"
            "driver.quit()\n"
        )
        try:
            proc = subprocess.run(
                ['python', '-c', selenium_script, target],
                capture_output=True, text=True, timeout=timeout
            )
            if proc.returncode == 0 and proc.stdout.strip():
                rendered_urls = _extract_urls_from_source(proc.stdout)
                new_urls = rendered_urls - self.endpoints
                self.endpoints.update(rendered_urls)
                print(f"{Colors.success(f'JS render (Selenium): {len(new_urls)} new URLs')}")
                return
        except FileNotFoundError:
            pass
        except subprocess.TimeoutExpired:
            if self.engine.config.get('verbose'):
                print(f"{Colors.warning('Selenium timed out')}")
        except Exception as e:
            if self.engine.config.get('verbose'):
                print(f"{Colors.warning(f'Selenium unavailable: {e}')}")

        print(f"{Colors.info('JS rendering: no supported browser engine found')}")

    # ──────────────────────────────────────
    # Passive URL Collection (gau/waybackurls)
    # ──────────────────────────────────────

    def _passive_url_collection(self, target: str, timeout: int = 60):
        """Collect historically known URLs for the target domain from
        public web archives (Wayback Machine, Common Crawl, etc.).

        Tries the ``gau`` CLI tool first, then ``waybackurls``, and
        finally falls back to a direct query against the Wayback Machine
        CDX API when neither tool is installed.

        Parameters
        ----------
        target : str
            The target URL whose domain will be queried.
        timeout : int
            Maximum seconds to wait for each subprocess / HTTP call.
        """
        print(f"{Colors.info('Collecting passive URLs from web archives...')}")

        target_domain = urlparse(target).netloc
        collected = set()

        # ── Strategy 1: gau ──
        try:
            proc = subprocess.run(
                ['gau', '--subs', target_domain],
                capture_output=True, text=True, timeout=timeout
            )
            if proc.returncode == 0 and proc.stdout.strip():
                for line in proc.stdout.strip().splitlines():
                    url = line.strip()
                    if url and target_domain in urlparse(url).netloc:
                        collected.add(url)
                if collected:
                    new_urls = collected - self.endpoints
                    self.endpoints.update(collected)
                    print(f"{Colors.success(f'Passive (gau): {len(new_urls)} new URLs collected')}")
                    return
        except FileNotFoundError:
            if self.engine.config.get('verbose'):
                print(f"{Colors.info('gau not found, trying waybackurls...')}")
        except subprocess.TimeoutExpired:
            if self.engine.config.get('verbose'):
                print(f"{Colors.warning('gau timed out')}")
        except Exception as e:
            if self.engine.config.get('verbose'):
                print(f"{Colors.warning(f'gau error: {e}')}")

        # ── Strategy 2: waybackurls ──
        try:
            proc = subprocess.run(
                ['waybackurls', target_domain],
                capture_output=True, text=True, timeout=timeout
            )
            if proc.returncode == 0 and proc.stdout.strip():
                for line in proc.stdout.strip().splitlines():
                    url = line.strip()
                    if url and target_domain in urlparse(url).netloc:
                        collected.add(url)
                if collected:
                    new_urls = collected - self.endpoints
                    self.endpoints.update(collected)
                    print(f"{Colors.success(f'Passive (waybackurls): {len(new_urls)} new URLs collected')}")
                    return
        except FileNotFoundError:
            if self.engine.config.get('verbose'):
                print(f"{Colors.info('waybackurls not found, using Wayback CDX API...')}")
        except subprocess.TimeoutExpired:
            if self.engine.config.get('verbose'):
                print(f"{Colors.warning('waybackurls timed out')}")
        except Exception as e:
            if self.engine.config.get('verbose'):
                print(f"{Colors.warning(f'waybackurls error: {e}')}")

        # ── Strategy 3: Wayback Machine CDX API direct query ──
        try:
            cdx_url = (
                f"https://web.archive.org/cdx/search/cdx"
                f"?url={quote(target_domain, safe='')}/*"
                f"&output=json&fl=original&collapse=urlkey&limit=500"
            )
            req = Request(cdx_url, headers={
                'User-Agent': 'ATOMIC-Framework/8.0'
            })
            with urlopen(req, timeout=timeout) as response:
                data = json.loads(response.read().decode('utf-8', errors='replace'))
                # First row is the header ["original"], skip it
                for row in data[1:]:
                    if row:
                        url = row[0]
                        if target_domain in urlparse(url).netloc:
                            collected.add(url)
        except Exception as e:
            if self.engine.config.get('verbose'):
                print(f"{Colors.warning(f'Wayback CDX API error: {e}')}")

        if collected:
            new_urls = collected - self.endpoints
            self.endpoints.update(collected)
            print(f"{Colors.success(f'Passive (CDX API): {len(new_urls)} new URLs collected')}")
        else:
            print(f"{Colors.info('Passive collection: no URLs found')}")

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
