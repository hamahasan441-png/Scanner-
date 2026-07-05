#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK
Advanced Web Crawler Module
"""

import re
from urllib.parse import urljoin, urlparse, parse_qs


from config import Colors

# File extensions that indicate XML-related resources (WSDL, XSD, WADL, feeds, SVG)
_XML_EXTENSIONS = (".wsdl", ".xsd", ".wadl", ".xml", ".svg", ".rss", ".atom", ".soap")


class Crawler:
    """Web Crawler with endpoint graph tracking"""

    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.visited = set()
        self.forms = []
        self.parameters = []
        self.resources = {
            "scripts": set(),
            "stylesheets": set(),
            "images": set(),
            "iframes": set(),
            "media": set(),
            "comments": [],
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
                if self.engine.config.get("verbose"):
                    print(f"{Colors.warning(f'Crawl limit reached ({max_urls} URLs)')}")
                break

            url, current_depth = to_visit.pop(0)

            if url in self.visited or current_depth > depth:
                continue

            self.visited.add(url)

            if len(self.visited) % 100 == 0 and self.engine.config.get("verbose"):
                print(f"{Colors.info(f'Crawl progress: {len(self.visited)} URLs visited')}")

            try:
                response = self.requester.request(url, "GET")
                if not response:
                    continue

                soup = BeautifulSoup(response.text, "html.parser")
                self._process_page(soup, url, response, base_domain, to_visit, current_depth, depth)

            except Exception as e:
                if self.engine.config.get("verbose"):
                    print(f"{Colors.error(f'Crawl error: {e}')}")

        return self.visited, self.forms, self.parameters

    def _process_page(self, soup, url, response, base_domain, to_visit, current_depth, depth):
        """Extract all data from a single crawled page."""
        self._extract_forms(soup, url)
        self._extract_parameters(url)

        if current_depth < depth:
            self._enqueue_links(soup, url, base_domain, to_visit, current_depth, depth)

        self._extract_resources(soup, url)
        self._extract_api_endpoints(soup, url)
        self._extract_hidden_params(soup, url)
        self._extract_comments(soup, url)
        self._extract_link_params(soup, url, base_domain, to_visit, current_depth, depth)
        self._extract_js_params(soup, url)
        self._extract_xml_links(soup, url, base_domain, to_visit, current_depth, depth)
        self._extract_source_maps(soup, url, response)
        self._update_graph(url, response, soup)

        # Deep scan extraction methods
        self._extract_json_body_params(soup, url)
        self._extract_multipart_params(soup, url)
        self._extract_websocket_endpoints(soup, url)
        self._extract_api_versions(soup, url)
        self._extract_response_params(response, url)
        self._mine_deep_js_params(soup, url)

    def _enqueue_links(self, soup, url, base_domain, to_visit, current_depth, depth):
        """Extract <a> links and add same-domain URLs to the crawl queue."""
        for link in soup.find_all("a", href=True):
            full_url = urljoin(url, link["href"])
            if urlparse(full_url).netloc == base_domain and full_url not in self.visited:
                to_visit.append((full_url, current_depth + 1))

        return self.visited, self.forms, self.parameters

    def _extract_forms(self, soup, url: str):
        """Extract forms from page"""
        for form in soup.find_all("form"):
            action = form.get("action", "")
            form_url = urljoin(url, action) if action else url
            method = form.get("method", "get").lower()

            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    inputs.append(
                        {
                            "name": name,
                            "type": inp.get("type", "text"),
                            "value": inp.get("value", ""),
                        }
                    )

            self.forms.append(
                {
                    "url": form_url,
                    "method": method,
                    "inputs": inputs,
                }
            )

            # Add to parameters
            for inp in inputs:
                self.parameters.append((form_url, method, inp["name"], inp.get("value", ""), "form"))

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
                    self.parameters.append((url, "get", name, value, "url_param"))

        # Extract path parameters (numeric/UUID segments that are likely IDs)
        self._extract_path_params(url)

    # Patterns that identify path segments likely to be injectable IDs
    _PATH_ID_RE = re.compile(r"^\d+$")
    _PATH_UUID_RE = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$", re.I)
    _PATH_HEX_HASH_RE = re.compile(r"^[0-9a-f]{32,64}$", re.I)
    _PATH_SLUG_ID_RE = re.compile(r"^\d+-[\w-]+$")
    _PATH_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]{16,}={1,2}$")
    _PATH_SHORT_TOKEN_RE = re.compile(r"^(?=.*[a-zA-Z])(?=.*\d)[a-zA-Z0-9]{8,12}$")

    _JS_NOISE = frozenset(
        (
            "true",
            "false",
            "null",
            "undefined",
            "constructor",
            "prototype",
            "length",
            "name",
            "type",
            "value",
        )
    )

    def _extract_path_params(self, url: str):
        """Extract injectable path segments as testable parameters.

        Detects numeric IDs, UUIDs, hex hashes, slugified IDs, Base64
        segments, and short alphanumeric tokens.
        Example: /users/42/profile → param 'path[1]' with value '42'
        """
        parsed = urlparse(url)
        segments = [s for s in parsed.path.split("/") if s]
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
                self.parameters.append((url, "get", f"path[{idx}]", seg, "path_param"))

    def _extract_resources(self, soup, url: str):
        """Extract referenced resources: scripts, stylesheets, images, iframes, media"""
        # Script sources
        for script in soup.find_all("script", src=True):
            src = urljoin(url, script["src"])
            self.resources["scripts"].add(src)

        # Stylesheet links
        for link in soup.find_all("link", href=True):
            href = urljoin(url, link["href"])
            rel = " ".join(link.get("rel", []))
            if "stylesheet" in rel:
                self.resources["stylesheets"].add(href)

        # Images
        for img in soup.find_all("img", src=True):
            self.resources["images"].add(urljoin(url, img["src"]))

        # Iframes
        for iframe in soup.find_all("iframe", src=True):
            self.resources["iframes"].add(urljoin(url, iframe["src"]))

        # Video / audio / source elements
        for tag in soup.find_all(["video", "audio", "source"], src=True):
            self.resources["media"].add(urljoin(url, tag["src"]))

    def _extract_api_endpoints(self, soup, url: str):
        """Extract API endpoints from JavaScript.

        Regex patterns cover REST, GraphQL, gRPC-web, Swagger/OpenAPI,
        WebSocket, fetch/axios/jQuery/XMLHttpRequest, and template-
        literal URL patterns — curated from top GitHub security repos.
        """
        for script in soup.find_all("script"):
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
                    r"`([^`]*\$\{[^`]*\}[^`]*)`",
                    # window.location / document.location assignments
                    r'(?:window|document)\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']',
                    # HTTP method calls on any object (.get/.post/.put/.delete)
                    r'\.\s*(?:get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']',
                    # ── Additional patterns from GitHub security repos ──
                    # OpenAPI / Swagger definition URLs
                    r'["\'](/swagger[^"\']*)["\']',
                    r'["\'](/openapi[^"\']*)["\']',
                    r'["\'](/api-docs[^"\']*)["\']',
                    # gRPC-web & protobuf endpoints
                    r'["\'](/grpc[^"\']*)["\']',
                    r'["\'](/twirp/[^"\']+)["\']',
                    # Next.js / Nuxt.js API routes
                    r'["\'](/api/[a-z][a-zA-Z0-9_/]*)["\']',
                    r'["\'](/_next/data/[^"\']+)["\']',
                    # AWS API Gateway patterns
                    r'["\'](https?://[a-z0-9]+\.execute-api\.[^"\']+)["\']',
                    # Firebase / Firestore patterns
                    r'["\'](https?://[^"\']*firebaseio\.com[^"\']*)["\']',
                    r'["\'](https?://[^"\']*firestore\.googleapis\.com[^"\']*)["\']',
                    # OAuth / token endpoints
                    r'["\'](/oauth/[^"\']+)["\']',
                    r'["\'](/auth/[^"\']+)["\']',
                    r'["\'](/token[^"\']*)["\']',
                    r'["\'](/\.well-known/[^"\']+)["\']',
                    # Internal/admin endpoints
                    r'["\'](/internal/[^"\']+)["\']',
                    r'["\'](/admin/api[^"\']*)["\']',
                    r'["\'](/debug/[^"\']+)["\']',
                    r'["\'](/actuator[^"\']*)["\']',
                    # Config / environment exposure
                    r'["\'](/config[^"\']*\.(?:json|yml|yaml|xml))["\']',
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
                                    self.parameters.append((api_url, "get", p_name, p_val, "api_extracted"))
                        else:
                            self.parameters.append((api_url, "get", "", "", "api"))

                # Extract JSON keys as potential hidden parameters
                json_patterns = [
                    r'["\'](\w+)["\']\s*:\s*["\']',
                    r"data\.\s*(\w+)",
                    r"params\.\s*(\w+)",
                ]
                for pattern in json_patterns:
                    matches = re.findall(pattern, script.string)
                    for param_name in matches:
                        if len(param_name) > 1 and param_name not in ("true", "false", "null", "undefined"):
                            self.parameters.append((url, "get", param_name, "", "js_extracted"))

    def _extract_hidden_params(self, soup, url: str):
        """Extract hidden input fields and meta parameters"""
        # Hidden inputs
        for inp in soup.find_all("input", {"type": "hidden"}):
            name = inp.get("name")
            if name:
                self.parameters.append((url, "get", name, inp.get("value", ""), "hidden_input"))

        # Data attributes
        for elem in soup.find_all(attrs={"data-url": True}):
            data_url = urljoin(url, elem.get("data-url", ""))
            self.parameters.append((data_url, "get", "", "", "data_attr"))

        # Meta tags with URLs
        for meta in soup.find_all("meta", content=True):
            content = meta.get("content", "")
            if content.startswith(("http://", "https://", "/")):
                meta_url = urljoin(url, content)
                self.parameters.append((meta_url, "get", "", "", "meta"))

    def _extract_comments(self, soup, url: str):
        """Extract HTML comments that may reveal paths, debug info, or credentials"""
        from bs4 import Comment

        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        for comment in comments:
            text = comment.strip()
            if text:
                self.resources["comments"].append({"url": url, "comment": text})

    def _extract_js_params(self, soup, url: str):
        """Extract parameter names from JavaScript source.

        Looks for URLSearchParams usage, FormData appends, object keys in
        request bodies, and getElementById/getElementsByName form value
        extractions.
        """
        for script in soup.find_all("script"):
            if not script.string:
                continue
            src = script.string

            # URLSearchParams .get/.set/.has
            for match in re.findall(r'\.(?:get|set|has)\(["\'](\w+)["\']\)', src):
                self.parameters.append((url, "get", match, "", "js_param"))

            # URLSearchParams/FormData .append('name', ...)
            for match in re.findall(r'\.append\(["\'](\w+)["\']\s*,', src):
                self.parameters.append((url, "post", match, "", "js_formdata"))

            # Object keys in body/data/params: { key: ... }
            body_blocks = re.findall(r"(?:body|data|params)\s*[:=]\s*\{([^}]+)\}", src)
            for block in body_blocks:
                for key in re.findall(r'["\']?(\w+)["\']?\s*:', block):
                    if key not in self._JS_NOISE:
                        self.parameters.append((url, "post", key, "", "js_body_key"))

            # getElementById / getElementsByName form value extraction
            for match in re.findall(r'getElement(?:ById|sByName)\(["\'](\w+)["\']\)', src):
                self.parameters.append((url, "get", match, "", "js_dom_param"))

    def _extract_link_params(
        self, soup, url: str, base_domain: str, to_visit: list, current_depth: int, max_depth: int
    ):
        """Extract additional navigable links from the page.

        Covers <link> canonical/alternate, <base> href, <area> href,
        and data-href / data-src / data-action attributes on any element.
        Discovered same-domain URLs are added to the crawl queue.
        """
        found_urls = set()

        # <link rel="canonical|alternate"> tags
        for link in soup.find_all("link", href=True):
            rel = " ".join(link.get("rel", []))
            if any(r in rel for r in ("canonical", "alternate")):
                found_urls.add(urljoin(url, link["href"]))

        # <base> href
        base_tag = soup.find("base", href=True)
        if base_tag:
            found_urls.add(urljoin(url, base_tag["href"]))

        # <area> href
        for area in soup.find_all("area", href=True):
            found_urls.add(urljoin(url, area["href"]))

        # data-href, data-src, data-action on any element
        for attr in ("data-href", "data-src", "data-action"):
            for elem in soup.find_all(attrs={attr: True}):
                val = elem.get(attr, "")
                if val:
                    found_urls.add(urljoin(url, val))

        # Enqueue same-domain links for crawling
        for found in found_urls:
            if urlparse(found).netloc == base_domain:
                self.parameters.append((found, "get", "", "", "link_extracted"))
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
        path = parsed.path or "/"

        if path not in self.endpoint_graph:
            self.endpoint_graph[path] = {
                "url": url,
                "methods": set(),
                "params": set(),
                "auth_state": "unknown",
                "related": set(),
            }

        entry = self.endpoint_graph[path]
        entry["methods"].add("GET")

        # Track parameters from URL query
        if parsed.query:
            for name in parse_qs(parsed.query):
                entry["params"].add(name)

        # Track form parameters and their methods
        for form in soup.find_all("form"):
            method = form.get("method", "get").upper()
            entry["methods"].add(method)
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    entry["params"].add(name)

        # Detect authentication state from response
        if response:
            auth_hints = ["login", "signin", "auth", "session", "token"]
            path_lower = path.lower()
            headers_lower = str(response.headers).lower()

            if any(h in path_lower for h in auth_hints):
                entry["auth_state"] = "auth_endpoint"
                self.auth_indicators.add(url)
            elif "set-cookie" in headers_lower:
                entry["auth_state"] = "sets_cookie"
            elif response.status_code in (401, 403):
                entry["auth_state"] = "requires_auth"
                self.auth_indicators.add(url)

        # Track related links from this page
        for link in soup.find_all("a", href=True):
            href = urljoin(url, link["href"])
            href_path = urlparse(href).path or "/"
            if href_path != path:
                entry["related"].add(href_path)

    def get_graph_summary(self):
        """Return a plain-text summary of the endpoint graph.

        Format: User → /login → token → /api/user → /admin
        """
        lines = []
        for path, data in self.endpoint_graph.items():
            methods = ",".join(sorted(data["methods"]))
            params = ",".join(sorted(data["params"])) if data["params"] else "none"
            related = " → ".join(sorted(data["related"])[:5]) if data["related"] else "none"
            lines.append(f"  [{methods}] {path} (params: {params}, auth: {data['auth_state']}) → {related}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # XML / WSDL / SOAP / Feed link extraction
    # ------------------------------------------------------------------

    def _extract_xml_links(self, soup, url: str, base_domain: str, to_visit: list, current_depth: int, max_depth: int):
        """Extract XML-related links: WSDL, XSD, SOAP endpoints, RSS/Atom feeds, SVG files.

        Covers:
        - <link> tags with type="application/rss+xml" or "application/atom+xml"
        - <link> or <a> references to .wsdl, .xsd, .wadl, .xml files
        - Inline references to WSDL/SOAP service URLs
        - SVG file references (potential XXE/XSS vector)
        """
        found_urls = set()

        # Feed auto-discovery links
        for link in soup.find_all("link", type=True):
            link_type = link.get("type", "").lower()
            href = link.get("href", "")
            if href and any(ft in link_type for ft in ("rss", "atom", "xml")):
                found_urls.add(urljoin(url, href))

        # Any link ending in common XML-related extensions
        for tag in soup.find_all(["a", "link", "script", "embed", "object"], href=True):
            href = tag.get("href", "") or tag.get("src", "") or tag.get("data", "")
            if href and any(href.lower().endswith(ext) for ext in _XML_EXTENSIONS):
                found_urls.add(urljoin(url, href))

        for tag in soup.find_all(["a", "link", "script", "embed", "object", "img"], src=True):
            src = tag.get("src", "")
            if src and any(src.lower().endswith(ext) for ext in _XML_EXTENSIONS):
                found_urls.add(urljoin(url, src))

        # Extract WSDL references from inline JavaScript
        for script in soup.find_all("script"):
            if script.string:
                for match in re.findall(r'["\']([^"\']*\.(?:wsdl|xsd|wadl))["\']', script.string, re.IGNORECASE):
                    found_urls.add(urljoin(url, match))
                # SOAP endpoint patterns
                for match in re.findall(r'["\']([^"\']+\?wsdl)["\']', script.string, re.IGNORECASE):
                    found_urls.add(urljoin(url, match))

        # Enqueue same-domain XML links for crawling
        for found in found_urls:
            parsed = urlparse(found)
            if parsed.netloc == base_domain and parsed.scheme in ("http", "https"):
                self.parameters.append((found, "get", "", "", "xml_link"))
                if current_depth < max_depth and found not in self.visited:
                    to_visit.append((found, current_depth + 1))

    # ------------------------------------------------------------------
    # Source Map extraction
    # ------------------------------------------------------------------

    def _extract_source_maps(self, soup, url: str, response):
        """Extract JavaScript source map URLs from script tags and SourceMap headers.

        Source maps can reveal original source code, internal paths,
        API endpoints, and configuration details.
        """
        found_maps = set()

        # Check SourceMap / X-SourceMap response headers
        if response and hasattr(response, "headers"):
            for header_name in ("SourceMap", "X-SourceMap"):
                map_url = response.headers.get(header_name, "")
                if map_url:
                    found_maps.add(urljoin(url, map_url))

        # Check for //# sourceMappingURL= in inline scripts
        for script in soup.find_all("script"):
            if script.string:
                for match in re.findall(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)', script.string):
                    found_maps.add(urljoin(url, match))

        # Check for sourceMappingURL in external script src (.js files)
        for script in soup.find_all("script", src=True):
            src = script.get("src", "")
            if src:
                # Try the conventional .js.map extension
                map_url = urljoin(url, src + ".map")
                found_maps.add(map_url)

        # Add discovered source maps as resources
        for map_url in found_maps:
            self.resources["scripts"].add(map_url)
            self.parameters.append((map_url, "get", "", "", "source_map"))

    # ------------------------------------------------------------------
    # Deep scan extraction methods
    # ------------------------------------------------------------------

    def _extract_json_body_params(self, soup, url):
        """Extract JSON body parameters from JavaScript fetch/axios calls.

        Looks for fetch() with body:{}, JSON.stringify patterns, and
        Content-Type: application/json headers to discover nested keys
        that are used in POST requests.
        """
        for script in soup.find_all("script"):
            if not script.string:
                continue
            src = script.string

            # Pattern 1: fetch/axios with JSON body objects
            # e.g. fetch(url, {body: JSON.stringify({key1: val, key2: val})})
            stringify_blocks = re.findall(
                r'JSON\.stringify\s*\(\s*\{([^}]+)\}', src
            )
            for block in stringify_blocks:
                for key in re.findall(r'["\']?(\w+)["\']?\s*:', block):
                    if key not in self._JS_NOISE and len(key) > 1:
                        self.parameters.append((url, "post", key, "", "json_body"))

            # Pattern 2: body: { key: value } in fetch options
            body_blocks = re.findall(
                r'body\s*:\s*\{([^}]+)\}', src
            )
            for block in body_blocks:
                for key in re.findall(r'["\']?(\w+)["\']?\s*:', block):
                    if key not in self._JS_NOISE and len(key) > 1:
                        self.parameters.append((url, "post", key, "", "json_body"))

            # Pattern 3: Content-Type: application/json with data objects
            # Look for headers with json content type near data/payload objects
            if "application/json" in src:
                data_blocks = re.findall(
                    r'(?:data|payload|requestBody)\s*[:=]\s*\{([^}]+)\}', src
                )
                for block in data_blocks:
                    for key in re.findall(r'["\']?(\w+)["\']?\s*:', block):
                        if key not in self._JS_NOISE and len(key) > 1:
                            self.parameters.append((url, "post", key, "", "json_body"))

            # Pattern 4: axios.post(url, {key: value})
            axios_bodies = re.findall(
                r'axios\.(?:post|put|patch)\s*\([^,]+,\s*\{([^}]+)\}', src
            )
            for block in axios_bodies:
                for key in re.findall(r'["\']?(\w+)["\']?\s*:', block):
                    if key not in self._JS_NOISE and len(key) > 1:
                        self.parameters.append((url, "post", key, "", "json_body"))

    def _extract_multipart_params(self, soup, url):
        """Extract multipart/form-data form fields and file upload inputs.

        Identifies forms with enctype="multipart/form-data" and extracts
        field names including file inputs as testable parameters.
        File inputs use source='multipart_file' to distinguish them.
        """
        for form in soup.find_all("form"):
            enctype = (form.get("enctype") or "").lower()
            if "multipart/form-data" in enctype:
                action = form.get("action", "")
                form_url = urljoin(url, action) if action else url
                method = form.get("method", "post").lower()

                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if name:
                        input_type = inp.get("type", "text").lower()
                        # Use a distinct source for file inputs instead of
                        # appending a duplicate generic entry.
                        if input_type == "file":
                            self.parameters.append(
                                (form_url, method, name, "", "multipart_file")
                            )
                        else:
                            self.parameters.append(
                                (form_url, method, name, "", "multipart")
                            )

        # Also check JS for FormData usage
        for script in soup.find_all("script"):
            if not script.string:
                continue
            # formData.append('fieldName', ...)
            for match in re.findall(
                r'[Ff]orm[Dd]ata.*?\.append\s*\(\s*["\'](\w+)["\']', script.string
            ):
                self.parameters.append((url, "post", match, "", "multipart"))

    def _extract_websocket_endpoints(self, soup, url):
        """Extract WebSocket connection URLs from JavaScript.

        Detects new WebSocket(...), io.connect(...), SockJS patterns,
        and registers them with source='websocket'.
        """
        for script in soup.find_all("script"):
            if not script.string:
                continue
            src = script.string

            # new WebSocket('ws://...' or 'wss://...')
            ws_patterns = [
                r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']',
                r'io\s*\.\s*connect\s*\(\s*["\']([^"\']+)["\']',
                r'io\s*\(\s*["\']([^"\']+)["\']',
                r'SockJS\s*\(\s*["\']([^"\']+)["\']',
                r'new\s+SockJS\s*\(\s*["\']([^"\']+)["\']',
                r'["\'](\w+s?://[^"\']*(?:socket|ws|realtime)[^"\']*)["\']',
            ]

            for pattern in ws_patterns:
                for match in re.findall(pattern, src):
                    ws_url = urljoin(url, match)
                    self.parameters.append((ws_url, "get", "", "", "websocket"))

    def _extract_api_versions(self, soup, url):
        """Identify API versioning patterns and generate alternate versions.

        Finds /v1/, /v2/, /api/v3/ etc in links and scripts, then
        generates alternate version URLs to test for deprecated insecure
        endpoints.
        """
        version_pattern = re.compile(r'/v(\d+)/')
        found_versioned = set()

        # Check all links on the page
        for link in soup.find_all("a", href=True):
            href = link.get("href", "")
            full_url = urljoin(url, href)
            match = version_pattern.search(full_url)
            if match:
                found_versioned.add(full_url)

        # Check script content for versioned API paths
        for script in soup.find_all("script"):
            if not script.string:
                continue
            # Find versioned paths in strings
            for match in re.findall(r'["\']([^"\']*?/v\d+/[^"\']*)["\']', script.string):
                full_url = urljoin(url, match)
                found_versioned.add(full_url)

        # For each versioned URL, generate alternate versions
        for versioned_url in found_versioned:
            match = version_pattern.search(versioned_url)
            if match:
                current_version = int(match.group(1))
                # Generate v1 through v(current+1) to check for deprecated/beta
                for v in range(1, min(current_version + 2, 10)):
                    if v != current_version:
                        alt_url = version_pattern.sub(f'/v{v}/', versioned_url, count=1)
                        self.parameters.append(
                            (alt_url, "get", "", "", "api_version")
                        )
            # Also register the original
            self.parameters.append(
                (versioned_url, "get", "", "", "api_version")
            )

    # Common output-only JSON field names that servers typically do not accept
    # as input parameters.  Filtering these reduces scan noise on verbose APIs.
    _RESPONSE_PARAM_NOISE = frozenset((
        "id", "created_at", "updated_at", "deleted_at", "timestamp",
        "created", "updated", "modified", "version", "etag",
        "avatar_url", "gravatar_id", "html_url", "url",
        "total_count", "count", "total", "size",
        "sha", "hash", "checksum", "digest",
        "status", "state", "message", "description",
        "node_id", "ref", "object", "tree",
    ))

    def _extract_response_params(self, response, url):
        """Analyze HTTP response headers and body for parameter hints.

        Examines Link headers, X-* headers with IDs, JSON response keys,
        and pagination patterns to discover additional injection points.
        Applies a noise filter to skip common output-only field names.
        """
        if not response:
            return

        headers = response.headers if hasattr(response, "headers") else {}

        # Link header parsing (pagination, related resources)
        link_header = headers.get("Link", "") or headers.get("link", "")
        if link_header:
            # Extract URLs from Link header: <url>; rel="next"
            for match in re.findall(r'<([^>]+)>', link_header):
                link_url = urljoin(url, match)
                parsed = urlparse(link_url)
                if parsed.query:
                    for name, values in parse_qs(parsed.query).items():
                        for val in values:
                            self.parameters.append(
                                (link_url, "get", name, val, "response_extracted")
                            )

        # X-* headers that may contain IDs or tokens
        for header_name, header_value in headers.items():
            lower_name = header_name.lower()
            if lower_name.startswith("x-") and header_value:
                # Headers like X-Request-ID, X-Correlation-ID hint at params
                param_hint = lower_name.replace("x-", "").replace("-", "_")
                self.parameters.append(
                    (url, "get", param_hint, header_value, "response_extracted")
                )

        # JSON response key extraction
        text = response.text if hasattr(response, "text") else ""
        if text:
            # Look for JSON-like key patterns in response body
            json_keys = re.findall(r'"(\w{2,30})"\s*:', text)
            seen = set()
            for key in json_keys:
                if (key not in seen
                        and key not in self._JS_NOISE
                        and key not in self._RESPONSE_PARAM_NOISE):
                    seen.add(key)
                    self.parameters.append(
                        (url, "get", key, "", "response_extracted")
                    )

            # Pagination patterns: page, limit, offset, cursor, after, before
            pagination_params = re.findall(
                r'["\']?(page|limit|offset|cursor|after|before|per_page|page_size)["\']?\s*[:=]\s*["\']?(\w+)',
                text
            )
            for pname, pval in pagination_params:
                self.parameters.append(
                    (url, "get", pname, pval, "response_extracted")
                )

    def _mine_deep_js_params(self, soup, url):
        """Perform deeper JavaScript analysis for parameter discovery.

        Covers: object destructuring patterns, GraphQL query variables,
        route definitions with path parameters, and REST client configs.
        """
        for script in soup.find_all("script"):
            if not script.string:
                continue
            src = script.string

            # Pattern 1: Object destructuring: const {param1, param2} = ...
            destructure_blocks = re.findall(
                r'(?:const|let|var)\s*\{\s*([^}]+)\}\s*=', src
            )
            for block in destructure_blocks:
                for key in re.findall(r'(\w+)', block):
                    if key not in self._JS_NOISE and len(key) > 1:
                        self.parameters.append((url, "get", key, "", "deep_js"))

            # Pattern 2: GraphQL variables: variables: {key: value}
            gql_vars = re.findall(
                r'variables\s*:\s*\{([^}]+)\}', src
            )
            for block in gql_vars:
                for key in re.findall(r'["\']?(\w+)["\']?\s*:', block):
                    if key not in self._JS_NOISE and len(key) > 1:
                        self.parameters.append((url, "post", key, "", "deep_js"))

            # Pattern 3: Route definitions with path params
            # e.g. path: '/users/:id', '/api/:resource/:id'
            route_paths = re.findall(
                r'path\s*:\s*["\']([^"\']+)["\']', src
            )
            for rpath in route_paths:
                for param in re.findall(r':(\w+)', rpath):
                    self.parameters.append((url, "get", param, "", "deep_js"))

            # Pattern 4: Express/Koa style route params
            # router.get('/users/:userId', ...)
            router_routes = re.findall(
                r'(?:router|app)\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
                src
            )
            for rpath in router_routes:
                for param in re.findall(r':(\w+)', rpath):
                    self.parameters.append((url, "get", param, "", "deep_js"))

            # Pattern 5: GraphQL query/mutation field names
            gql_fields = re.findall(
                r'(?:query|mutation)\s+\w+\s*\(\s*([^)]+)\)', src
            )
            for block in gql_fields:
                for var in re.findall(r'\$(\w+)', block):
                    self.parameters.append((url, "post", var, "", "deep_js"))

            # Pattern 6: State management keys (Redux/Vuex actions)
            state_keys = re.findall(
                r'(?:dispatch|commit)\s*\(\s*["\'](\w+)["\']', src
            )
            for key in state_keys:
                if len(key) > 1 and key not in self._JS_NOISE:
                    self.parameters.append((url, "get", key, "", "deep_js"))
