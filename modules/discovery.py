#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v9.0 - ULTIMATE EDITION
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
import concurrent.futures
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse, quote
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


from config import Colors, Payloads

# ────────────────────────────────────────────
# Common paths for directory brute-forcing
# ────────────────────────────────────────────
COMMON_PATHS = [
    # ── Admin / Management ──
    "/admin",
    "/administrator",
    "/admin/login",
    "/admin/dashboard",
    "/cpanel",
    "/dashboard",
    "/manage",
    "/manager",
    "/panel",
    "/control",
    "/wp-admin",
    "/webadmin",
    "/sysadmin",
    "/console",
    "/h2-console",
    "/monitoring",
    "/nagios",
    "/system",
    "/webmail",
    # ── Login / Auth ──
    "/login",
    "/signin",
    "/signup",
    "/register",
    "/auth",
    "/oauth",
    "/logout",
    "/password",
    "/forgot-password",
    "/reset-password",
    "/account",
    "/profile",
    "/user",
    "/users",
    "/me",
    "/sso",
    "/saml",
    "/cas",
    "/openid",
    # ── API Endpoints ──
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/api/latest",
    "/graphql",
    "/graphiql",
    "/playground",
    "/__graphql",
    "/rest",
    "/soap",
    "/rpc",
    "/jsonrpc",
    "/xmlrpc",
    "/swagger",
    "/swagger-ui",
    "/swagger-ui.html",
    "/api-docs",
    "/openapi.json",
    "/api/docs",
    "/api/schema",
    "/swagger.json",
    "/swagger.yaml",
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/webhook",
    "/callback",
    "/notify",
    # ── Configuration / Debug ──
    "/config",
    "/configuration",
    "/settings",
    "/env",
    "/.env",
    "/debug",
    "/trace",
    "/status",
    "/health",
    "/healthcheck",
    "/info",
    "/server-info",
    "/server-status",
    "/phpinfo.php",
    "/metrics",
    "/stats",
    "/monitor",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/actuator/heapdump",
    "/actuator/mappings",
    "/_debug",
    "/__debug__",
    "/debug/pprof",
    "/_profiler",
    "/_wdt",
    # ── Backup / Development ──
    "/backup",
    "/backups",
    "/bak",
    "/old",
    "/temp",
    "/tmp",
    "/test",
    "/testing",
    "/dev",
    "/development",
    "/staging",
    "/archive",
    "/archives",
    "/legacy",
    "/deprecated",
    "/.git",
    "/.git/config",
    "/.git/HEAD",
    "/.svn",
    "/.hg",
    "/.DS_Store",
    "/web.config",
    "/.htaccess",
    "/.htpasswd",
    "/Thumbs.db",
    # ── WordPress ──
    "/wp-login.php",
    "/wp-content",
    "/wp-content/plugins",
    "/wp-content/themes",
    "/wp-content/uploads",
    "/wp-includes",
    "/wp-json",
    "/wp-json/wp/v2/users",
    "/xmlrpc.php",
    "/wp-cron.php",
    "/wp-links-opml.php",
    "/wp-content/debug.log",
    "/readme.html",
    # ── Laravel ──
    "/storage",
    "/storage/logs",
    "/storage/logs/laravel.log",
    "/storage/framework",
    "/bootstrap/cache",
    "/_ide_helper.php",
    "/artisan",
    # ── Django ──
    "/admin",
    "/static",
    "/media",
    "/__pycache__",
    # ── Rails ──
    "/public/assets",
    "/public/uploads",
    "/db",
    "/config",
    "/config/database.yml",
    "/config/secrets.yml",
    "/config/master.key",
    # ── ASP.NET ──
    "/App_Data",
    "/App_Code",
    "/bin",
    "/obj",
    "/Global.asax",
    "/Default.aspx",
    "/elmah.axd",
    # ── Java / Spring / Tomcat ──
    "/WEB-INF",
    "/WEB-INF/web.xml",
    "/META-INF",
    "/catalina.out",
    "/manager/html",
    # ── Common CMS / framework paths ──
    "/joomla",
    "/drupal",
    "/magento",
    "/ghost",
    "/vendor",
    "/node_modules",
    "/bower_components",
    "/composer.json",
    "/package.json",
    # ── File / Media / Uploads ──
    "/uploads",
    "/upload",
    "/files",
    "/media",
    "/static",
    "/assets",
    "/images",
    "/img",
    "/css",
    "/js",
    "/public",
    "/private",
    "/storage",
    "/data",
    "/userfiles",
    "/usercontent",
    "/user_uploads",
    "/attachments",
    "/documents",
    "/reports",
    "/download",
    "/downloads",
    "/export",
    "/import",
    # ── Database / Cache Tools ──
    "/phpmyadmin",
    "/pma",
    "/adminer",
    "/sqladmin",
    "/redis",
    "/memcached",
    "/elasticsearch",
    "/solr",
    "/kibana",
    "/mongo-express",
    "/couchdb",
    # ── Error / Fallback ──
    "/404",
    "/500",
    "/403",
    "/401",
    "/error",
    "/errors",
    # ── CI/CD / Docker ──
    "/Dockerfile",
    "/docker-compose.yml",
    "/Jenkinsfile",
    "/.github",
    "/.gitlab-ci.yml",
    "/.circleci",
    # ── Well-known / Standards ──
    "/robots.txt",
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/crossdomain.xml",
    "/security.txt",
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/humans.txt",
    "/ads.txt",
    "/app-ads.txt",
    "/favicon.ico",
    "/manifest.json",
    "/browserconfig.xml",
    # ── Log Files ──
    "/logs",
    "/log",
    "/debug.log",
    "/error.log",
    "/access.log",
    "/application.log",
    "/server.log",
    # ── Source & IDE Artifacts ──
    "/.idea",
    "/.vscode",
    "/.project",
    "/.classpath",
    "/.editorconfig",
    "/tsconfig.json",
    "/webpack.config.js",
    # ── Terraform / Cloud Config ──
    "/terraform.tfstate",
    "/terraform.tfvars",
    "/.aws/credentials",
    "/.kube/config",
    "/credentials.json",
    "/service-account.json",
]


# ── Custom-404 detection thresholds ──────────────────────────────────────
_CUSTOM_404_LENGTH_THRESHOLD = 50  # max byte-length diff from canary
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
        self.robots_paths = {"allowed": set(), "disallowed": set()}
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
        modules_cfg = self.engine.config.get("modules", {})
        if modules_cfg.get("dir_brute", False):
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

        # 10. Backup file discovery
        self._discover_backup_files(base_url)

        # 11. JavaScript endpoint and secret mining
        self._mine_js_endpoints(target)

        # 12. XML / WSDL / SOAP service discovery
        self._discover_xml_services(base_url)

        # 13. API specification discovery (OpenAPI, AsyncAPI, RAML, etc.)
        self._discover_api_specs(base_url)

        # 14. Sensitive XML configuration file discovery
        self._discover_sensitive_xml(base_url)

        # 15. RSS / Atom feed discovery and URL extraction
        self._discover_feeds(base_url, target)

        # 16. Print structured report
        self._print_report(target)

    # ──────────────────────────────────────
    # robots.txt
    # ──────────────────────────────────────

    def _parse_robots(self, base_url: str):
        """Fetch and parse robots.txt for hidden or interesting paths."""
        robots_url = f"{base_url}/robots.txt"
        print(f"{Colors.info(f'Fetching {robots_url}...')}")

        try:
            resp = self.requester.request(robots_url, "GET")
            if resp and resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            self.robots_paths["disallowed"].add(path)
                            self.endpoints.add(urljoin(base_url, path))
                    elif line.lower().startswith("allow:"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            self.robots_paths["allowed"].add(path)
                            self.endpoints.add(urljoin(base_url, path))
                    elif line.lower().startswith("sitemap:"):
                        sitemap_url = line.split(":", 1)[1].strip()
                        # Re-attach scheme when the value looked like "//host/path"
                        if sitemap_url.startswith("//"):
                            sitemap_url = urlparse(base_url).scheme + ":" + sitemap_url
                        self._parse_sitemap_url(sitemap_url)

                total = len(self.robots_paths["disallowed"]) + len(self.robots_paths["allowed"])
                print(f"{Colors.success(f'robots.txt: {total} paths discovered')}")
            else:
                print(f"{Colors.info('robots.txt not found or inaccessible')}")
        except Exception as e:
            if self.engine.config.get("verbose"):
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
            resp = self.requester.request(sitemap_url, "GET")
            if resp and resp.status_code == 200 and resp.text.strip():
                try:
                    root = ET.fromstring(resp.text)
                except ET.ParseError:
                    if self.engine.config.get("verbose"):
                        print(f"{Colors.warning('Sitemap XML parse failed')}")
                    return

                # Handle sitemap index (contains <sitemap><loc>...</loc></sitemap>)
                ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
                for sitemap_tag in root.findall(".//sm:sitemap/sm:loc", ns):
                    if sitemap_tag.text:
                        self._parse_sitemap_url(sitemap_tag.text.strip())

                # Handle url entries
                for url_tag in root.findall(".//sm:url/sm:loc", ns):
                    if url_tag.text:
                        loc = url_tag.text.strip()
                        self.sitemap_urls.add(loc)
                        self.endpoints.add(loc)

                # Try without namespace (some sitemaps lack it)
                if not self.sitemap_urls:
                    for loc_tag in root.iter("loc"):
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
            if self.engine.config.get("verbose"):
                print(f"{Colors.error(f'sitemap.xml error: {e}')}")

    # ──────────────────────────────────────
    # Directory brute-force
    # ──────────────────────────────────────

    def _dir_brute(self, base_url: str):
        """Probe common paths to discover hidden endpoints.

        Uses a baseline 404 fingerprint to avoid false positives from
        custom error pages that return HTTP 200.

        The path list is the union of the built-in ``COMMON_PATHS`` and
        curated ``Payloads.DISCOVERY_PATHS_EXTENDED`` (sourced from
        SecLists, dirsearch, and PayloadsAllTheThings).
        """
        # Merge built-in + GitHub-curated extended paths (no duplicates)
        all_paths = list(COMMON_PATHS)
        _seen = set(all_paths)
        for p in Payloads.DISCOVERY_PATHS_EXTENDED:
            if p not in _seen:
                all_paths.append(p)
                _seen.add(p)

        # Optionally fetch live SecLists common wordlist
        try:
            from utils.github_wordlists import fetch_wordlist

            gh_common = fetch_wordlist("seclists_common", max_lines=300)
            for p in gh_common:
                entry = p if p.startswith("/") else f"/{p}"
                if entry not in _seen:
                    all_paths.append(entry)
                    _seen.add(entry)
        except Exception:
            pass

        print(f"{Colors.info(f'Directory brute-force ({len(all_paths)} paths)...')}")
        found = 0

        # Build a baseline "not found" fingerprint so we can detect
        # custom 404 pages that return 200.
        baseline_len = 0
        baseline_words: set = set()
        try:
            canary_url = urljoin(base_url, "/atomic_nonexistent_path_9f3a1b")
            canary_resp = self.requester.request(canary_url, "GET")
            if canary_resp:
                baseline_len = len(canary_resp.text)
                baseline_words = set(canary_resp.text.lower().split()[:50])
        except Exception:
            pass

        for path in all_paths:
            full_url = urljoin(base_url, path)

            # Skip if already discovered
            if full_url in self.endpoints:
                continue

            try:
                resp = self.requester.request(full_url, "GET")
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

                    if self.engine.config.get("verbose"):
                        print(f"  {Colors.GREEN}[{resp.status_code}]{Colors.RESET} {path}")
            except Exception as e:
                if self.engine.config.get("verbose"):
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
            self.endpoints.add(form.get("url", ""))

        # Resource references
        for category, items in crawler.resources.items():
            if category == "comments":
                for entry in items:
                    self.interesting_findings.append(f"HTML comment on {entry['url']}: {entry['comment'][:120]}")
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
            "auth": (
                "/login",
                "/signin",
                "/auth",
                "/oauth",
                "/token",
                "/session",
                "/sso",
                "/password",
                "/reset",
                "/forgot",
                "/register",
                "/signup",
            ),
            "admin": ("/admin", "/dashboard", "/manage", "/panel", "/control", "/cpanel", "/wp-admin", "/console"),
            "api": (
                "/api", "/graphql", "/rest", "/swagger", "/openapi", "/v1/", "/v2/", "/v3/", "/api-docs",
                "/grpc", "/twirp", "/jsonrpc", "/xmlrpc", "/asyncapi", "/raml",
            ),
            "xml_svc": (
                "/wsdl", "?wsdl", ".wsdl", "/soap", "/axis2", "/axis/", "/cxf/",
                "/ws/", ".xsd", ".wadl", "/service.asmx", "/service.svc",
            ),
            "upload": ("/upload", "/file", "/media", "/attach", "/import", "/export"),
            "config": (
                "/config",
                "/.env",
                "/settings",
                "/debug",
                "/phpinfo",
                "/server-info",
                "/server-status",
                "/trace",
                "/actuator",
                "/health",
                "/log4j.xml",
                "/logback.xml",
                "/hibernate.cfg.xml",
                "/persistence.xml",
                "/tomcat-users.xml",
            ),
            "data": ("/backup", "/dump", "/database", "/db", "/phpmyadmin", "/adminer", "/sql"),
            "scm": ("/.git", "/.svn", "/.hg", "/.DS_Store", "/web.config", "/.htaccess"),
            "feed": ("/rss", "/atom", "/feed", ".rss", ".atom"),
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
        risk_level = "LOW"
        if category_counts.get("config") or category_counts.get("scm"):
            risk_level = "CRITICAL"
        elif category_counts.get("admin") or category_counts.get("data"):
            risk_level = "HIGH"
        elif category_counts.get("api") or category_counts.get("auth") or category_counts.get("xml_svc"):
            risk_level = "MEDIUM"

        self._analysis_result = {
            "category_counts": dict(category_counts),
            "priority_endpoints": priority_endpoints,
            "risk_level": risk_level,
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
            if self.engine.config.get("verbose"):
                print(f"{Colors.info('aiohttp not installed – skipping async crawl')}")
            return set()

        print(f"{Colors.info('Running async web crawl...')}")

        target_domain = urlparse(seed_urls[0]).netloc if seed_urls else ""
        discovered = set()

        async def _fetch(session, url):
            """Fetch a single URL and return its text content."""
            try:
                # SSL verification disabled for security testing targets that
                # commonly use self-signed certificates. This is intentional for
                # a vulnerability scanner — production clients should verify SSL.
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
                    if resp.status == 200 and "text" in resp.content_type:
                        return await resp.text(errors="replace")
            except Exception:
                pass
            return ""

        async def _extract_links(html, base_url):
            """Extract same-domain links from HTML using regex."""
            links = set()
            # Match href="..." and src="..."
            for match in re.finditer(r'(?:href|src)\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE):
                link = match.group(1)
                absolute = urljoin(base_url, link)
                parsed = urlparse(absolute)
                if parsed.netloc == target_domain and parsed.scheme in ("http", "https"):
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
            if self.engine.config.get("verbose"):
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
            if self.engine.config.get("verbose"):
                print(f"{Colors.info('bs4 not installed – skipping enhanced link extraction')}")
            return

        print(f"{Colors.info('Running enhanced link extraction...')}")

        target_parsed = urlparse(target)
        target_domain = target_parsed.netloc

        try:
            resp = self.requester.request(target, "GET")
            if not resp or resp.status_code != 200:
                return
        except Exception as e:
            if self.engine.config.get("verbose"):
                print(f"{Colors.error(f'Enhanced extraction fetch error: {e}')}")
            return

        html = resp.text

        # Select parser: prefer lxml, fall back to html.parser
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            soup = BeautifulSoup(html, "html.parser")

        found = set()

        # Tag-attribute pairs to extract URLs from
        tag_attrs = [
            ("a", "href"),
            ("form", "action"),
            ("script", "src"),
            ("link", "href"),
            ("img", "src"),
            ("iframe", "src"),
            ("area", "href"),
        ]

        for tag_name, attr in tag_attrs:
            for tag in soup.find_all(tag_name):
                value = tag.get(attr)
                if value:
                    absolute = urljoin(target, value)
                    parsed = urlparse(absolute)
                    if parsed.netloc == target_domain and parsed.scheme in ("http", "https"):
                        found.add(absolute)

        # meta http-equiv="refresh" content="0;url=..."
        for meta in soup.find_all("meta", attrs={"http-equiv": re.compile(r"refresh", re.IGNORECASE)}):
            content = meta.get("content", "")
            match = re.search(r"url\s*=\s*(.+)", content, re.IGNORECASE)
            if match:
                url = match.group(1).strip().strip("'\"")
                absolute = urljoin(target, url)
                parsed = urlparse(absolute)
                if parsed.netloc == target_domain and parsed.scheme in ("http", "https"):
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

        for script in soup.find_all("script"):
            js_text = script.string or ""
            for pattern in js_patterns:
                for match in re.finditer(pattern, js_text):
                    url = match.group(1)
                    absolute = urljoin(target, url)
                    parsed = urlparse(absolute)
                    if parsed.netloc == target_domain and parsed.scheme in ("http", "https"):
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
                if parsed.netloc == target_domain and parsed.scheme in ("http", "https"):
                    urls.add(absolute)
            return urls

        # ── Strategy 1: Playwright via Python ──
        playwright_script = (
            "import sys, json\n"
            "from playwright.sync_api import sync_playwright\n"
            "with sync_playwright() as p:\n"
            "    browser = p.chromium.launch(headless=True, args=['--no-sandbox'])\n"
            "    page = browser.new_page()\n"
            "    page.goto(sys.argv[1], wait_until='networkidle', timeout=20000)\n"
            "    print(page.content())\n"
            "    browser.close()\n"
        )
        try:
            proc = subprocess.run(
                ["python", "-c", playwright_script, target], capture_output=True, text=True, timeout=timeout
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
            if self.engine.config.get("verbose"):
                print(f"{Colors.warning('Playwright timed out')}")
        except Exception as e:
            if self.engine.config.get("verbose"):
                print(f"{Colors.warning(f'Playwright unavailable: {e}')}")

        # ── Strategy 2: Puppeteer via Node.js ──
        puppeteer_script = (
            "const puppeteer = require('puppeteer');"
            "(async () => {"
            "  // --no-sandbox required for containerized / CI environments\n"
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
                ["node", "-e", puppeteer_script, target], capture_output=True, text=True, timeout=timeout
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
            if self.engine.config.get("verbose"):
                print(f"{Colors.warning('Puppeteer timed out')}")
        except Exception as e:
            if self.engine.config.get("verbose"):
                print(f"{Colors.warning(f'Puppeteer unavailable: {e}')}")

        # ── Strategy 3: Selenium via Python ──
        selenium_script = (
            "import sys, time\n"
            "from selenium import webdriver\n"
            "from selenium.webdriver.chrome.options import Options\n"
            "opts = Options()\n"
            "opts.add_argument('--headless')\n"
            "# WARNING: --no-sandbox disables Chrome's security sandbox.\n"
            "# Required for containerized/CI environments but reduces browser\n"
            "# security. Only use against trusted or controlled test targets.\n"
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
                ["python", "-c", selenium_script, target], capture_output=True, text=True, timeout=timeout
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
            if self.engine.config.get("verbose"):
                print(f"{Colors.warning('Selenium timed out')}")
        except Exception as e:
            if self.engine.config.get("verbose"):
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
            proc = subprocess.run(["gau", "--subs", target_domain], capture_output=True, text=True, timeout=timeout)
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
            if self.engine.config.get("verbose"):
                print(f"{Colors.info('gau not found, trying waybackurls...')}")
        except subprocess.TimeoutExpired:
            if self.engine.config.get("verbose"):
                print(f"{Colors.warning('gau timed out')}")
        except Exception as e:
            if self.engine.config.get("verbose"):
                print(f"{Colors.warning(f'gau error: {e}')}")

        # ── Strategy 2: waybackurls ──
        try:
            proc = subprocess.run(["waybackurls", target_domain], capture_output=True, text=True, timeout=timeout)
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
            if self.engine.config.get("verbose"):
                print(f"{Colors.info('waybackurls not found, using Wayback CDX API...')}")
        except subprocess.TimeoutExpired:
            if self.engine.config.get("verbose"):
                print(f"{Colors.warning('waybackurls timed out')}")
        except Exception as e:
            if self.engine.config.get("verbose"):
                print(f"{Colors.warning(f'waybackurls error: {e}')}")

        # ── Strategy 3: Wayback Machine CDX API direct query ──
        try:
            cdx_url = (
                f"https://web.archive.org/cdx/search/cdx"
                f"?url={quote(target_domain, safe='')}/*"
                f"&output=json&fl=original&collapse=urlkey&limit=500"
            )
            req = Request(cdx_url, headers={"User-Agent": "ATOMIC-Framework/9.0"})
            with urlopen(req, timeout=timeout) as response:
                data = json.loads(response.read().decode("utf-8", errors="replace"))
                # First row is the header ["original"], skip it
                for row in data[1:]:
                    if row:
                        url = row[0]
                        if target_domain in urlparse(url).netloc:
                            collected.add(url)
        except Exception as e:
            if self.engine.config.get("verbose"):
                print(f"{Colors.warning(f'Wayback CDX API error: {e}')}")

        if collected:
            new_urls = collected - self.endpoints
            self.endpoints.update(collected)
            print(f"{Colors.success(f'Passive (CDX API): {len(new_urls)} new URLs collected')}")
        else:
            print(f"{Colors.info('Passive collection: no URLs found')}")

    # ──────────────────────────────────────
    # Backup File Discovery
    # ──────────────────────────────────────

    def _discover_backup_files(self, base_url: str):
        """Probe for common backup files that leak source code or secrets."""
        backup_patterns = [
            # Source code archives
            "/backup.zip",
            "/backup.tar.gz",
            "/backup.sql",
            "/dump.sql",
            "/database.sql",
            "/db.sql",
            "/site.zip",
            "/www.zip",
            "/public.zip",
            "/source.zip",
            "/code.zip",
            "/app.zip",
            "/backup.tar",
            "/backup.gz",
            "/backup.7z",
            "/backup.rar",
            # Config file backups
            "/.env.bak",
            "/.env.backup",
            "/.env.old",
            "/.env.example",
            "/wp-config.php.bak",
            "/wp-config.php.old",
            "/wp-config.php.save",
            "/config.php.bak",
            "/config.yml.bak",
            "/settings.py.bak",
            "/web.config.bak",
            "/web.config.old",
            "/appsettings.json.bak",
            "/application.yml.bak",
            # Editor swap/backup files
            "/.htaccess.bak",
            "/.htpasswd.bak",
            "/index.php.bak",
            "/index.php~",
            "/index.php.swp",
            # VCS leftovers
            "/.git/config",
            "/.git/HEAD",
            "/.git/index",
            "/.svn/entries",
            "/.svn/wc.db",
            "/.hg/store/data",
            # Database dumps
            "/mysqldump.sql",
            "/pgdump.sql",
            "/data.json",
            "/export.csv",
        ]

        print(f"{Colors.info('Probing for backup/source files...')}")
        found = 0

        # Build baseline for custom 404 detection
        baseline_len = 0
        try:
            canary_resp = self.requester.request(urljoin(base_url, "/atomic_backup_test_nonexist.bak"), "GET")
            if canary_resp:
                baseline_len = len(canary_resp.text)
        except Exception:
            pass

        for path in backup_patterns:
            full_url = urljoin(base_url, path)
            if full_url in self.endpoints:
                continue
            try:
                resp = self.requester.request(full_url, "GET")
                if resp and resp.status_code == 200:
                    # Skip custom 404 pages
                    if baseline_len and abs(len(resp.text) - baseline_len) < 100:
                        continue
                    # Check for real content indicators
                    content_type = resp.headers.get("Content-Type", "").lower()
                    if (
                        any(
                            ct in content_type
                            for ct in [
                                "octet-stream",
                                "zip",
                                "gzip",
                                "tar",
                                "sql",
                                "json",
                                "yaml",
                                "xml",
                                "text/plain",
                            ]
                        )
                        or len(resp.text) > 500
                    ):
                        self.endpoints.add(full_url)
                        found += 1
                        # Report as finding
                        from core.engine import Finding

                        severity = (
                            "CRITICAL"
                            if any(kw in path for kw in [".sql", ".env", ".zip", ".tar", "config", "wp-config"])
                            else "HIGH"
                        )
                        finding = Finding(
                            technique="Discovery (Backup File Exposed)",
                            url=full_url,
                            severity=severity,
                            confidence=0.85,
                            param="N/A",
                            payload=path,
                            evidence=f"Backup file accessible: {path} ({len(resp.text)} bytes, "
                            f"Content-Type: {content_type[:50]})",
                        )
                        self.engine.add_finding(finding)
            except Exception:
                continue

        if found:
            print(f"{Colors.success(f'Backup file discovery: {found} files found')}")

    # ──────────────────────────────────────
    # JavaScript Endpoint Mining
    # ──────────────────────────────────────

    def _mine_js_endpoints(self, target: str):
        """Extract API endpoints and secrets from JavaScript files.

        Collects JS file URLs from discovered endpoints, script tags,
        and dynamic import patterns, then applies comprehensive regex
        patterns to extract API routes, endpoints, and leaked secrets.
        """
        print(f"{Colors.info('Mining JavaScript files for endpoints and secrets...')}")

        # Collect JS file URLs from already-discovered endpoints
        js_urls = set()
        for ep in self.endpoints:
            if ep.endswith(".js") and "jquery" not in ep.lower() and "bootstrap" not in ep.lower():
                js_urls.add(ep)

        # Also look for script tags and dynamic imports in the main page
        try:
            resp = self.requester.request(target, "GET")
            if resp and resp.text:
                # Standard <script src="..."> tags
                for match in re.finditer(r'<script[^>]*src=["\']([^"\']+\.js)["\']', resp.text, re.IGNORECASE):
                    js_url = urljoin(target, match.group(1))
                    js_urls.add(js_url)
                # Dynamic imports: import("...") / import('...')
                for match in re.finditer(r'import\s*\(\s*["\']([^"\']+\.js)["\']', resp.text):
                    js_url = urljoin(target, match.group(1))
                    js_urls.add(js_url)
                # Inline script blocks — extract endpoints directly
                for script_match in re.finditer(
                    r"<script[^>]*>(.*?)</script[^>]*>", resp.text, re.DOTALL | re.IGNORECASE
                ):
                    self._extract_js_inline_endpoints(
                        script_match.group(1), target, js_urls
                    )
        except Exception:
            pass

        if not js_urls:
            return

        # ── Comprehensive endpoint patterns ──
        endpoint_patterns = [
            # API path patterns in quotes
            r'["\'](/api/[a-zA-Z0-9_/.\-]+)["\']',
            r'["\'](/v[1-9]/[a-zA-Z0-9_/.\-]+)["\']',
            # Generic two-segment paths
            r'["\'](?:https?://[^"\']+)?(/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+)["\']',
            # HTTP client calls
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
            r'\.(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
            # URL/endpoint assignment
            r'url\s*[:=]\s*["\']([^"\']+)["\']',
            r'endpoint\s*[:=]\s*["\']([^"\']+)["\']',
            r'href\s*[:=]\s*["\']([^"\']+)["\']',
            r'action\s*[:=]\s*["\']([^"\']+)["\']',
            # REST/GraphQL/RPC routes
            r'["\'](/(?:rest|graphql|gql|rpc|webhook|callback)/[a-zA-Z0-9_/.\-%]+)["\']',
            # Auth and user management routes
            r'["\'](/(?:auth|login|logout|register|signup|signin|signout|forgot|reset|verify'
            r'|confirm|activate|profile|account|user|users|settings|preferences)'
            r'(?:/[a-zA-Z0-9_\-%]+)*)["\']',
            # CRUD operation routes
            r'["\'](/(?:create|read|update|delete|edit|add|remove|save|publish|upload'
            r'|download|export|import|backup|restore|migrate|deploy)'
            r'(?:/[a-zA-Z0-9_\-%]+)*)["\']',
            # Admin / config / debug routes
            r'["\'](/(?:admin|manage|control|system|config|setting|debug|test|monitor'
            r'|status|health|metrics|internal)'
            r'(?:/[a-zA-Z0-9_\-%]+)*)["\']',
            # Template literal paths: `${baseUrl}/api/...`
            r'`[^`]*(/(?:api|v[1-9]|rest|graphql)/[a-zA-Z0-9_/${\-}.]+)`',
            # XMLHttpRequest.open
            r'\.open\s*\(\s*["\'][A-Z]+["\']\s*,\s*["\']([^"\']+)["\']',
        ]

        secret_patterns = [
            (
                r'(?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key|auth[_-]?token)\s*[:=]\s*["\']([^"\']{8,})["\']',
                "API Key/Secret",
            ),
            (r'(?:aws_access_key_id|aws_secret_access_key)\s*[:=]\s*["\']([^"\']+)["\']', "AWS Credential"),
            (r'(?:firebase|supabase|stripe)[\w]*\s*[:=]\s*["\']([^"\']{10,})["\']', "Service Key"),
            (r'(?:google_api_key|gcp_api_key|google_maps_key)\s*[:=]\s*["\']([^"\']{10,})["\']', "Google API Key"),
            (r'(?:slack_token|slack_webhook)\s*[:=]\s*["\']([^"\']{10,})["\']', "Slack Token"),
            (r'(?:twilio_sid|twilio_token|sendgrid_key)\s*[:=]\s*["\']([^"\']{10,})["\']', "Messaging Service Key"),
        ]

        new_endpoints = set()
        secrets_found = []

        base_url = f"{urlparse(target).scheme}://{urlparse(target).netloc}"

        for js_url in list(js_urls)[:30]:  # Limit to 30 JS files
            try:
                resp = self.requester.request(js_url, "GET")
                if not resp or not resp.text:
                    continue
                js_content = resp.text

                # Extract endpoints
                for pattern in endpoint_patterns:
                    for match in re.finditer(pattern, js_content):
                        path = match.group(1)
                        if path.startswith("/") and len(path) > 2:
                            full_url = urljoin(base_url, path)
                            if full_url not in self.endpoints:
                                new_endpoints.add(full_url)

                # Extract secrets
                for pattern, secret_type in secret_patterns:
                    for match in re.finditer(pattern, js_content, re.IGNORECASE):
                        secrets_found.append(
                            {
                                "type": secret_type,
                                "file": js_url,
                                "value": match.group(1)[:20] + "...",
                            }
                        )
            except Exception:
                continue

        if new_endpoints:
            self.endpoints.update(new_endpoints)
            print(f"{Colors.success(f'JS mining: {len(new_endpoints)} new endpoints from {len(js_urls)} JS files')}")

        if secrets_found:
            from core.engine import Finding

            for secret in secrets_found[:5]:  # Cap findings
                finding = Finding(
                    technique="Discovery (JS Secret Exposure)",
                    url=secret["file"],
                    severity="HIGH",
                    confidence=0.75,
                    param="N/A",
                    payload=secret["type"],
                    evidence=f"{secret['type']} found in JS: {secret['value']}",
                )
                self.engine.add_finding(finding)
            print(f"{Colors.success(f'JS mining: {len(secrets_found)} secrets/keys found')}")

    @staticmethod
    def _extract_js_inline_endpoints(script_text, target, js_urls):
        """Extract JS file references from inline script blocks.

        Discovers dynamic imports, importScripts, and source map
        references inside ``<script>`` tags so they can be fetched
        and analyzed together with external JS files.
        """
        # Dynamic import("chunk-xxx.js")
        for match in re.finditer(r'import\s*\(\s*["\']([^"\']+\.js)["\']', script_text):
            js_urls.add(urljoin(target, match.group(1)))
        # importScripts("worker.js")
        for match in re.finditer(r'importScripts\s*\(\s*["\']([^"\']+\.js)["\']', script_text):
            js_urls.add(urljoin(target, match.group(1)))
        # sourceMappingURL=app.js.map (useful for source reconstruction)
        for match in re.finditer(r'sourceMappingURL=(\S+\.js\.map)', script_text):
            js_urls.add(urljoin(target, match.group(1)))

    # ──────────────────────────────────────
    # XML / WSDL / SOAP Service Discovery
    # ──────────────────────────────────────

    def _discover_xml_services(self, base_url: str):
        """Discover WSDL, SOAP, and XML-RPC service endpoints.

        Probes common WSDL/SOAP URL patterns and, when a WSDL document
        is found, parses it to extract additional service endpoints,
        operations, and port bindings.
        """
        print(f"{Colors.info('Probing for WSDL / SOAP / XML-RPC services...')}")

        wsdl_paths = [
            "/?wsdl",
            "/service.wsdl",
            "/services.wsdl",
            "/ws/service.wsdl",
            "/Service?wsdl",
            "/Service?WSDL",
            "/services/Service?wsdl",
            "/soap/Service?wsdl",
            "/ws/Service?wsdl",
            "/service.asmx?WSDL",
            "/service.svc?wsdl",
            "/service.svc?singleWsdl",
            "/wsdl",
            "/axis2/services/listServices",
            "/axis/services/",
            "/cxf/",
        ]

        # Build baseline for custom 404 detection
        baseline_len = 0
        try:
            canary_resp = self.requester.request(
                urljoin(base_url, "/atomic_wsdl_nonexist_probe_9f.wsdl"), "GET"
            )
            if canary_resp:
                baseline_len = len(canary_resp.text)
        except Exception:
            pass

        found = 0
        wsdl_content_list = []  # (url, text) pairs to parse later

        for path in wsdl_paths:
            full_url = urljoin(base_url, path)
            if full_url in self.endpoints:
                continue
            try:
                resp = self.requester.request(full_url, "GET")
                if resp and resp.status_code == 200 and resp.text.strip():
                    # Skip custom 404 pages
                    if baseline_len and abs(len(resp.text) - baseline_len) < 100:
                        continue
                    text = resp.text
                    content_type = resp.headers.get("Content-Type", "").lower()
                    is_xml = "xml" in content_type or text.strip().startswith("<?xml") or "<definitions" in text
                    is_wsdl = "<definitions" in text or "<wsdl:" in text or "schemas.xmlsoap.org" in text
                    is_service_list = "axis" in path and ("<service" in text.lower() or "available services" in text.lower())

                    if is_xml or is_wsdl or is_service_list or "xml" in content_type:
                        self.endpoints.add(full_url)
                        found += 1
                        if is_wsdl:
                            wsdl_content_list.append((full_url, text))

                        severity = "MEDIUM" if is_wsdl else "INFO"
                        from core.engine import Finding

                        finding = Finding(
                            technique="Discovery (WSDL/SOAP Service)",
                            url=full_url,
                            severity=severity,
                            confidence=0.85,
                            param="N/A",
                            payload=path,
                            evidence=f"XML service endpoint accessible: {path} "
                            f"({len(text)} bytes, Content-Type: {content_type[:50]})",
                        )
                        self.engine.add_finding(finding)
            except Exception:
                continue

        # Parse discovered WSDL documents for additional endpoints
        for wsdl_url, wsdl_text in wsdl_content_list:
            self._parse_wsdl_endpoints(wsdl_url, wsdl_text, base_url)

        if found:
            print(f"{Colors.success(f'WSDL/SOAP discovery: {found} service endpoints found')}")
        else:
            if self.engine.config.get("verbose"):
                print(f"{Colors.info('WSDL/SOAP discovery: no services found')}")

    def _parse_wsdl_endpoints(self, wsdl_url: str, wsdl_text: str, base_url: str):
        """Parse a WSDL document to extract service endpoints, ports, and operations."""
        try:
            root = ET.fromstring(wsdl_text)
        except ET.ParseError:
            return

        # Extract service locations from <soap:address location="...">
        soap_ns = {
            "soap": "http://schemas.xmlsoap.org/wsdl/soap/",
            "soap12": "http://schemas.xmlsoap.org/wsdl/soap12/",
            "wsdl": "http://schemas.xmlsoap.org/wsdl/",
            "http": "http://schemas.xmlsoap.org/wsdl/http/",
        }

        for ns_prefix in ("soap", "soap12"):
            ns = soap_ns.get(ns_prefix, "")
            for addr in root.iter(f"{{{ns}}}address"):
                loc = addr.get("location", "")
                if loc:
                    self.endpoints.add(loc)

        # Also try without namespace (some WSDLs lack proper namespace)
        for elem in root.iter():
            if "address" in elem.tag.lower():
                loc = elem.get("location", "")
                if loc and loc.startswith("http"):
                    self.endpoints.add(loc)

        # Extract operation names from <wsdl:operation name="...">
        operations = set()
        for elem in root.iter():
            if "operation" in elem.tag.lower():
                op_name = elem.get("name", "")
                if op_name:
                    operations.add(op_name)

        if operations and self.engine.config.get("verbose"):
            ops_str = ", ".join(sorted(operations)[:10])
            print(f"{Colors.info(f'  WSDL operations: {ops_str}')}")

        # Extract schema imports (XSD URLs)
        for elem in root.iter():
            tag_local = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            if tag_local in ("import", "include", "schemaLocation"):
                for attr in ("schemaLocation", "location"):
                    val = elem.get(attr, "")
                    if val:
                        schema_url = urljoin(wsdl_url, val)
                        self.endpoints.add(schema_url)

    # ──────────────────────────────────────
    # API Specification Discovery
    # ──────────────────────────────────────

    def _discover_api_specs(self, base_url: str):
        """Discover API specification files: OpenAPI, AsyncAPI, RAML, API Blueprint, Postman, HAR."""
        print(f"{Colors.info('Probing for API specification files...')}")

        spec_paths = [
            # OpenAPI / Swagger
            ("/swagger.json", "OpenAPI/Swagger"),
            ("/swagger.yaml", "OpenAPI/Swagger"),
            ("/openapi.json", "OpenAPI"),
            ("/openapi.yaml", "OpenAPI"),
            ("/openapi.yml", "OpenAPI"),
            ("/openapi/v3/api-docs", "OpenAPI 3"),
            ("/openapi/v3/api-docs.yaml", "OpenAPI 3"),
            ("/v2/api-docs", "Swagger 2"),
            ("/v3/api-docs", "OpenAPI 3"),
            ("/api-docs", "API Docs"),
            ("/api-docs/swagger.json", "Swagger"),
            ("/swagger-resources", "Swagger Resources"),
            ("/swagger-ui/swagger.json", "Swagger UI"),
            # AsyncAPI
            ("/asyncapi.json", "AsyncAPI"),
            ("/asyncapi.yaml", "AsyncAPI"),
            # RAML
            ("/api.raml", "RAML"),
            # API Blueprint
            ("/apiary.apib", "API Blueprint"),
            # Postman / Insomnia collections
            ("/collection.json", "Postman Collection"),
            ("/postman_collection.json", "Postman Collection"),
            ("/insomnia.json", "Insomnia Collection"),
            # HAR files
            ("/api.har", "HAR Archive"),
            # WADL
            ("/application.wadl", "WADL"),
            ("/api/application.wadl", "WADL"),
            ("/rest/application.wadl", "WADL"),
        ]

        # Build baseline for custom 404 detection
        baseline_len = 0
        try:
            canary_resp = self.requester.request(
                urljoin(base_url, "/atomic_apispec_nonexist_9f.json"), "GET"
            )
            if canary_resp:
                baseline_len = len(canary_resp.text)
        except Exception:
            pass

        found = 0

        for path, spec_type in spec_paths:
            full_url = urljoin(base_url, path)
            if full_url in self.endpoints:
                continue
            try:
                resp = self.requester.request(full_url, "GET")
                if resp and resp.status_code == 200 and resp.text.strip():
                    if baseline_len and abs(len(resp.text) - baseline_len) < 100:
                        continue
                    text = resp.text
                    content_type = resp.headers.get("Content-Type", "").lower()
                    # Validate it looks like a real spec, not a generic page
                    is_json_like = text.strip().startswith("{") and any(
                        kw in text[:2000] for kw in ['"openapi"', '"swagger"', '"asyncapi"', '"info"', '"paths"']
                    )
                    is_yaml_like = any(
                        kw in text[:2000] for kw in ["openapi:", "swagger:", "asyncapi:", "title:", "#%RAML"]
                    )
                    is_xml_like = "xml" in content_type or text.strip().startswith("<?xml")
                    is_spec = is_json_like or is_yaml_like or is_xml_like or "apib" in path

                    if is_spec or len(text) > 500:
                        self.endpoints.add(full_url)
                        found += 1

                        # Parse OpenAPI/Swagger for API endpoints
                        if is_json_like and any(kw in text[:2000] for kw in ['"paths"', '"openapi"', '"swagger"']):
                            self._extract_openapi_endpoints(full_url, text, base_url)

                        from core.engine import Finding

                        finding = Finding(
                            technique=f"Discovery (API Spec: {spec_type})",
                            url=full_url,
                            severity="MEDIUM",
                            confidence=0.85 if is_spec else 0.6,
                            param="N/A",
                            payload=path,
                            evidence=f"{spec_type} spec accessible: {path} "
                            f"({len(text)} bytes, Content-Type: {content_type[:50]})",
                        )
                        self.engine.add_finding(finding)
            except Exception:
                continue

        if found:
            print(f"{Colors.success(f'API spec discovery: {found} specification files found')}")
        else:
            if self.engine.config.get("verbose"):
                print(f"{Colors.info('API spec discovery: no spec files found')}")

    def _extract_openapi_endpoints(self, spec_url: str, spec_text: str, base_url: str):
        """Extract API endpoints from an OpenAPI/Swagger JSON specification."""
        try:
            import json as _json
            spec = _json.loads(spec_text)
        except (ValueError, TypeError):
            return

        # Extract paths
        paths = spec.get("paths", {})
        for path_key in paths:
            full_url = urljoin(base_url, path_key)
            self.endpoints.add(full_url)

        # Extract server URLs (OpenAPI 3.x)
        for server in spec.get("servers", []):
            server_url = server.get("url", "")
            if server_url and server_url.startswith("http"):
                self.endpoints.add(server_url)

        # Extract basePath (Swagger 2.x)
        base_path = spec.get("basePath", "")
        if base_path:
            self.endpoints.add(urljoin(base_url, base_path))

        if paths and self.engine.config.get("verbose"):
            print(f"{Colors.info(f'  OpenAPI: {len(paths)} path(s) extracted from spec')}")

    # ──────────────────────────────────────
    # Sensitive XML Configuration Discovery
    # ──────────────────────────────────────

    def _discover_sensitive_xml(self, base_url: str):
        """Discover exposed XML configuration files that may leak sensitive information."""
        print(f"{Colors.info('Probing for sensitive XML configuration files...')}")

        xml_paths = [
            # Java/J2EE
            ("/WEB-INF/web.xml", "Java Web Descriptor", "HIGH"),
            ("/WEB-INF/struts-config.xml", "Struts Configuration", "HIGH"),
            ("/META-INF/context.xml", "Tomcat Context", "MEDIUM"),
            ("/META-INF/MANIFEST.MF", "Java Manifest", "INFO"),
            # XML config files commonly exposed
            ("/crossdomain.xml", "Flash Cross-Domain Policy", "MEDIUM"),
            ("/clientaccesspolicy.xml", "Silverlight Cross-Domain", "MEDIUM"),
            ("/browserconfig.xml", "Browser Config", "INFO"),
            # Build / CI configs with potential secrets
            ("/pom.xml", "Maven POM", "MEDIUM"),
            ("/build.xml", "Ant Build", "MEDIUM"),
            ("/ivy.xml", "Ivy Dependencies", "INFO"),
            # Logging configs (may reveal paths/infrastructure)
            ("/log4j.xml", "Log4j Config", "MEDIUM"),
            ("/log4j2.xml", "Log4j2 Config", "MEDIUM"),
            ("/logback.xml", "Logback Config", "MEDIUM"),
            # ORM / persistence
            ("/hibernate.cfg.xml", "Hibernate Config", "HIGH"),
            ("/persistence.xml", "JPA Persistence", "HIGH"),
            # App server configs
            ("/server.xml", "Server Config", "HIGH"),
            ("/tomcat-users.xml", "Tomcat Users (credentials!)", "CRITICAL"),
            ("/context.xml", "Context Config", "MEDIUM"),
            ("/beans.xml", "CDI Beans Config", "INFO"),
            # Framework-specific
            ("/faces-config.xml", "JSF Config", "MEDIUM"),
            ("/tiles.xml", "Tiles Config", "INFO"),
            ("/struts.xml", "Struts2 Config", "MEDIUM"),
            ("/resin.xml", "Resin Config", "MEDIUM"),
            # .NET configs
            ("/Web.config", ".NET Web Config", "HIGH"),
            ("/web.config", ".NET Web Config", "HIGH"),
            ("/app.config", ".NET App Config", "MEDIUM"),
            # IIS
            ("/applicationHost.config", "IIS App Host", "HIGH"),
        ]

        # Build baseline for custom 404 detection
        baseline_len = 0
        try:
            canary_resp = self.requester.request(
                urljoin(base_url, "/atomic_xmlconf_nonexist_9f.xml"), "GET"
            )
            if canary_resp:
                baseline_len = len(canary_resp.text)
        except Exception:
            pass

        found = 0

        for path, desc, severity in xml_paths:
            full_url = urljoin(base_url, path)
            if full_url in self.endpoints:
                continue
            try:
                resp = self.requester.request(full_url, "GET")
                if resp and resp.status_code == 200 and resp.text.strip():
                    if baseline_len and abs(len(resp.text) - baseline_len) < 100:
                        continue
                    text = resp.text
                    content_type = resp.headers.get("Content-Type", "").lower()
                    # Verify it's actually XML content
                    is_xml = (
                        "xml" in content_type
                        or text.strip().startswith("<?xml")
                        or text.strip().startswith("<")
                    )
                    if is_xml and len(text) > 50:
                        self.endpoints.add(full_url)
                        found += 1
                        from core.engine import Finding

                        finding = Finding(
                            technique=f"Discovery (Sensitive XML: {desc})",
                            url=full_url,
                            severity=severity,
                            confidence=0.85,
                            param="N/A",
                            payload=path,
                            evidence=f"{desc} accessible: {path} ({len(text)} bytes)",
                        )
                        self.engine.add_finding(finding)
            except Exception:
                continue

        if found:
            print(f"{Colors.success(f'Sensitive XML discovery: {found} config files found')}")
        else:
            if self.engine.config.get("verbose"):
                print(f"{Colors.info('Sensitive XML discovery: no config files found')}")

    # ──────────────────────────────────────
    # RSS / Atom Feed Discovery
    # ──────────────────────────────────────

    def _discover_feeds(self, base_url: str, target: str):
        """Discover RSS/Atom feeds and extract URLs from feed entries."""
        print(f"{Colors.info('Probing for RSS/Atom feeds...')}")

        feed_paths = [
            "/rss", "/rss.xml", "/atom.xml", "/feed", "/feed.xml",
            "/feed/atom", "/feed/rss", "/feeds", "/blog/feed",
            "/blog/rss", "/news/feed", "/index.rss", "/index.atom",
            "/feed/posts/default", "/feeds/posts/default",
        ]

        # Also check <link> tags in the main page for feed auto-discovery
        feed_urls = set()
        try:
            resp = self.requester.request(target, "GET")
            if resp and resp.text:
                # Look for <link rel="alternate" type="application/rss+xml" ...>
                for match in re.finditer(
                    r'<link[^>]+type=["\']application/(?:rss|atom)\+xml["\'][^>]*href=["\']([^"\']+)["\']',
                    resp.text, re.IGNORECASE
                ):
                    feed_urls.add(urljoin(target, match.group(1)))
                # Also reversed attribute order
                for match in re.finditer(
                    r'<link[^>]+href=["\']([^"\']+)["\'][^>]*type=["\']application/(?:rss|atom)\+xml["\']',
                    resp.text, re.IGNORECASE
                ):
                    feed_urls.add(urljoin(target, match.group(1)))
        except Exception:
            pass

        # Combine auto-discovered + common paths
        for path in feed_paths:
            feed_urls.add(urljoin(base_url, path))

        found = 0
        for feed_url in feed_urls:
            if feed_url in self.endpoints:
                continue
            try:
                resp = self.requester.request(feed_url, "GET")
                if resp and resp.status_code == 200 and resp.text.strip():
                    text = resp.text
                    content_type = resp.headers.get("Content-Type", "").lower()
                    is_feed = (
                        "xml" in content_type
                        or "rss" in content_type
                        or "atom" in content_type
                        or "<rss" in text[:500]
                        or "<feed" in text[:500]
                        or "<channel" in text[:1000]
                    )
                    if is_feed:
                        self.endpoints.add(feed_url)
                        found += 1
                        # Extract URLs from feed entries
                        self._extract_feed_urls(text, feed_url)
            except Exception:
                continue

        if found:
            print(f"{Colors.success(f'Feed discovery: {found} RSS/Atom feeds found')}")
        else:
            if self.engine.config.get("verbose"):
                print(f"{Colors.info('Feed discovery: no feeds found')}")

    def _extract_feed_urls(self, feed_text: str, feed_url: str):
        """Extract URLs from RSS/Atom feed entries and add to endpoints."""
        try:
            root = ET.fromstring(feed_text)
        except ET.ParseError:
            # Fall back to regex extraction
            for match in re.finditer(r'<link[^>]*>([^<]+)</link>', feed_text):
                url = match.group(1).strip()
                if url.startswith("http"):
                    self.endpoints.add(url)
            return

        target_domain = urlparse(feed_url).netloc

        # RSS <item><link>...</link></item>
        for elem in root.iter():
            tag_local = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            if tag_local == "link":
                # Atom uses href attribute, RSS uses text content
                url = elem.get("href", "") or (elem.text or "").strip()
                if url and url.startswith("http"):
                    if urlparse(url).netloc == target_domain:
                        self.endpoints.add(url)
            elif tag_local == "guid" and elem.text:
                url = elem.text.strip()
                if url.startswith("http") and urlparse(url).netloc == target_domain:
                    self.endpoints.add(url)

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
        if self.robots_paths["disallowed"]:
            print(f"\n  {Colors.BOLD}robots.txt – Disallowed Paths (potential hidden content){Colors.RESET}")
            for path in sorted(self.robots_paths["disallowed"]):
                print(f"    {Colors.YELLOW}{path}{Colors.RESET}")

        # Smart analysis
        analysis = getattr(self, "_analysis_result", None)
        if analysis:
            risk = analysis["risk_level"]
            risk_color = {
                "CRITICAL": f"{Colors.RED}{Colors.BOLD}",
                "HIGH": Colors.RED,
                "MEDIUM": Colors.YELLOW,
                "LOW": Colors.GREEN,
            }.get(risk, Colors.WHITE)

            print(f"\n  {Colors.BOLD}Smart Analysis{Colors.RESET}")
            print(f"    Estimated attack surface risk: {risk_color}{risk}{Colors.RESET}")

            if analysis["category_counts"]:
                print(f"\n    {Colors.BOLD}Endpoint Categories:{Colors.RESET}")
                for cat, count in sorted(analysis["category_counts"].items(), key=lambda x: -x[1]):
                    print(f"      {cat:10s} : {count}")

            if analysis["priority_endpoints"]:
                print(f"\n    {Colors.BOLD}High-Priority Endpoints:{Colors.RESET}")
                for cat, ep in analysis["priority_endpoints"][:20]:
                    print(f"      [{cat:6s}] {ep}")

        # Interesting findings (e.g. HTML comments)
        if self.interesting_findings:
            print(f"\n  {Colors.BOLD}Interesting Findings{Colors.RESET}")
            for finding in self.interesting_findings[:15]:
                print(f"    {Colors.YELLOW}{finding}{Colors.RESET}")

        print(f"\n{Colors.BOLD}{'─'*60}{Colors.RESET}")
