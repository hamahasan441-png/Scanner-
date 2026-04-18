#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v10.0 - ULTIMATE EDITION
Phase 6 — Intelligence Enrichment

Aggregates technology fingerprinting, CVE matching, parameter context
enrichment, and network/tech exploit results into a unified
IntelligenceBundle consumed by the priority queue.

Usage:
    enricher = IntelligenceEnricher(engine)
    bundle = enricher.run(asset_graph, probe_result)
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

from config import Colors

# ── Tech Fingerprinting Rules ──────────────────────────────────────────

# HTTP header → technology mapping
HEADER_TECH_MAP = {
    "server": {
        "apache": ("Apache", "server"),
        "nginx": ("Nginx", "server"),
        "iis": ("IIS", "server"),
        "litespeed": ("LiteSpeed", "server"),
        "cloudflare": ("Cloudflare", "cdn"),
        "openresty": ("OpenResty", "server"),
        "caddy": ("Caddy", "server"),
    },
    "x-powered-by": {
        "php": ("PHP", "language"),
        "asp.net": ("ASP.NET", "framework"),
        "express": ("Express", "framework"),
        "next.js": ("Next.js", "framework"),
        "servlet": ("Java Servlet", "framework"),
    },
    "x-generator": {
        "wordpress": ("WordPress", "cms"),
        "drupal": ("Drupal", "cms"),
        "joomla": ("Joomla", "cms"),
        "wix": ("Wix", "cms"),
        "squarespace": ("Squarespace", "cms"),
    },
}

# Cookie name → technology mapping
COOKIE_TECH_MAP = {
    "phpsessid": ("PHP", "language"),
    "jsessionid": ("Java", "language"),
    "asp.net_sessionid": ("ASP.NET", "framework"),
    "laravel_session": ("Laravel", "framework"),
    "connect.sid": ("Express/Node.js", "framework"),
    "csrftoken": ("Django", "framework"),
    "rack.session": ("Ruby/Rack", "framework"),
    "_rails_session": ("Rails", "framework"),
    "ci_session": ("CodeIgniter", "framework"),
}

# HTML body patterns → technology mapping
HTML_TECH_PATTERNS = [
    (r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s*([\d.]*)', "WordPress", "cms"),
    (r'<meta\s+name=["\']generator["\']\s+content=["\']Drupal\s*([\d.]*)', "Drupal", "cms"),
    (r'<meta\s+name=["\']generator["\']\s+content=["\']Joomla', "Joomla", "cms"),
    (r"wp-content/", "WordPress", "cms"),
    (r"wp-includes/", "WordPress", "cms"),
    (r"/sites/default/files", "Drupal", "cms"),
    (r"react(?:\.production|\.development)", "React", "js_framework"),
    (r"vue(?:\.runtime|\.global)", "Vue.js", "js_framework"),
    (r"angular(?:\.min)?\.js", "AngularJS", "js_framework"),
    (r"ng-app|ng-controller", "AngularJS", "js_framework"),
    (r"jquery(?:\.min)?\.js", "jQuery", "js_library"),
    (r"bootstrap(?:\.min)?\.(?:js|css)", "Bootstrap", "css_framework"),
    (r"tailwind", "Tailwind CSS", "css_framework"),
]

# CSS class patterns → technology
CSS_CLASS_PATTERNS = {
    r'class=["\'][^"\']*(?:wp-|wordpress)[^"\']*["\']': ("WordPress", "cms"),
    r'class=["\'][^"\']*(?:views-|drupal)[^"\']*["\']': ("Drupal", "cms"),
    r'class=["\'][^"\']*(?:el-|ant-design)[^"\']*["\']': ("Element UI/Ant Design", "js_framework"),
}


# ── CVE Database (built-in subset of high-value CVEs) ──────────────────

CVE_DATABASE = [
    {
        "cve_id": "CVE-2024-4577",
        "tech": "PHP",
        "min_ver": "8.1.0",
        "max_ver": "8.3.8",
        "cvss": 9.8,
        "description": "PHP CGI argument injection (Windows)",
        "endpoint_hint": "/cgi-bin/",
    },
    {
        "cve_id": "CVE-2023-22515",
        "tech": "Confluence",
        "min_ver": "8.0.0",
        "max_ver": "8.5.1",
        "cvss": 10.0,
        "description": "Atlassian Confluence broken access control",
        "endpoint_hint": "/setup/",
    },
    {
        "cve_id": "CVE-2023-44487",
        "tech": "HTTP/2",
        "min_ver": "",
        "max_ver": "",
        "cvss": 7.5,
        "description": "HTTP/2 Rapid Reset DDoS",
        "endpoint_hint": "",
    },
    {
        "cve_id": "CVE-2023-46604",
        "tech": "Apache ActiveMQ",
        "min_ver": "5.0.0",
        "max_ver": "5.18.3",
        "cvss": 10.0,
        "description": "Apache ActiveMQ RCE",
        "endpoint_hint": ":61616",
    },
    {
        "cve_id": "CVE-2024-21887",
        "tech": "Ivanti Connect Secure",
        "min_ver": "",
        "max_ver": "",
        "cvss": 9.1,
        "description": "Ivanti Connect Secure command injection",
        "endpoint_hint": "/api/v1/totp/user-backup-code",
    },
    {
        "cve_id": "CVE-2023-50164",
        "tech": "Apache Struts",
        "min_ver": "2.0.0",
        "max_ver": "6.3.0",
        "cvss": 9.8,
        "description": "Apache Struts path traversal RCE",
        "endpoint_hint": "/upload",
    },
    {
        "cve_id": "CVE-2024-23897",
        "tech": "Jenkins",
        "min_ver": "",
        "max_ver": "2.442",
        "cvss": 9.8,
        "description": "Jenkins arbitrary file read",
        "endpoint_hint": "/cli",
    },
    {
        "cve_id": "CVE-2021-44228",
        "tech": "Log4j",
        "min_ver": "2.0.0",
        "max_ver": "2.17.0",
        "cvss": 10.0,
        "description": "Log4Shell RCE via JNDI injection",
        "endpoint_hint": "",
    },
    {
        "cve_id": "CVE-2023-3519",
        "tech": "Citrix NetScaler",
        "min_ver": "",
        "max_ver": "",
        "cvss": 9.8,
        "description": "Citrix NetScaler ADC RCE",
        "endpoint_hint": "/vpn/",
    },
    {
        "cve_id": "CVE-2023-27997",
        "tech": "FortiGate",
        "min_ver": "",
        "max_ver": "",
        "cvss": 9.8,
        "description": "FortiOS SSL VPN heap overflow",
        "endpoint_hint": "/remote/logincheck",
    },
]

# ── Param context weight rules ─────────────────────────────────────────

PARAM_CONTEXT_WEIGHTS = {
    "NUMERIC_ID": {
        "patterns": [r"(?i)^(id|uid|user_?id|item_?id|product_?id|cat_?id|order_?id|account_?id)$"],
        "weight": 0.9,
    },
    "AUTH_TOKEN": {
        "patterns": [r"(?i)^(token|auth|jwt|api_?key|session|bearer|access_?token|refresh_?token)$"],
        "weight": 1.0,
    },
    "FILE_PATH": {
        "patterns": [r"(?i)^(file|path|dir|directory|template|include|page|doc|document|resource)$"],
        "weight": 0.95,
    },
    "REDIRECT": {
        "patterns": [r"(?i)^(redirect|url|next|return|returnUrl|goto|dest|destination|continue|callback)$"],
        "weight": 0.85,
    },
    "REFLECTIVE": {
        "patterns": [r"(?i)^(q|search|query|keyword|name|msg|message|comment|title|body|text|content|input)$"],
        "weight": 0.8,
    },
    "COMMAND": {
        "patterns": [r"(?i)^(cmd|command|exec|run|shell|ping|host|ip|domain|action)$"],
        "weight": 0.95,
    },
}


# ── Data contracts ──────────────────────────────────────────────────────


@dataclass
class TechStack:
    """Detected technology stack."""

    cms: Optional[str] = None
    cms_version: Optional[str] = None
    language: Optional[str] = None
    framework: Optional[str] = None
    server: Optional[str] = None
    server_version: Optional[str] = None
    db: Optional[str] = None
    cdn: Optional[str] = None
    js_frameworks: List[str] = field(default_factory=list)
    all_techs: Dict[str, str] = field(default_factory=dict)  # name → category

    def to_dict(self) -> Dict:
        return {
            "cms": self.cms,
            "language": self.language,
            "framework": self.framework,
            "server": self.server,
            "db": self.db,
            "cdn": self.cdn,
            "js_frameworks": self.js_frameworks,
            "all_techs": self.all_techs,
        }


@dataclass
class CVEMatch:
    """A matched CVE."""

    cve_id: str = ""
    description: str = ""
    cvss: float = 0.0
    tech: str = ""
    endpoint_hint: str = ""

    def to_dict(self) -> Dict:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "cvss": self.cvss,
            "tech": self.tech,
            "endpoint_hint": self.endpoint_hint,
        }


@dataclass
class IntelligenceBundle:
    """Aggregated intelligence from Phase 6."""

    tech_stack: Optional[TechStack] = None
    cve_matches: List[CVEMatch] = field(default_factory=list)
    param_weights: Dict[str, float] = field(default_factory=dict)
    endpoint_types: Dict[str, str] = field(default_factory=dict)
    net_findings: List = field(default_factory=list)
    tech_findings: List = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "tech_stack": self.tech_stack.to_dict() if self.tech_stack else {},
            "cve_matches": [c.to_dict() for c in self.cve_matches],
            "param_weight_count": len(self.param_weights),
            "endpoint_type_count": len(self.endpoint_types),
            "net_findings": len(self.net_findings),
            "tech_findings": len(self.tech_findings),
        }


# ── TechFingerprinter ──────────────────────────────────────────────────


class TechFingerprinter:
    """Fingerprint technologies from HTTP responses."""

    def __init__(self, engine):
        self.engine = engine
        self.verbose = engine.config.get("verbose", False)

    def run(self, responses: List) -> TechStack:
        """Analyze responses and build TechStack."""
        stack = TechStack()

        for resp in responses:
            if resp is None:
                continue
            self._check_headers(resp, stack)
            self._check_cookies(resp, stack)
            if hasattr(resp, "text"):
                self._check_body(resp.text, stack)

        # Also pull from engine's context if available
        ctx = getattr(self.engine, "context", None)
        if ctx and hasattr(ctx, "detected_tech"):
            for tech_name in ctx.detected_tech:
                if tech_name not in stack.all_techs:
                    stack.all_techs[tech_name] = "detected"

        if self.verbose and stack.all_techs:
            print(f"{Colors.info(f'TechStack: {list(stack.all_techs.keys())}')}")

        return stack

    def _check_headers(self, resp, stack: TechStack):
        """Check response headers for technology signatures."""
        if not hasattr(resp, "headers"):
            return
        headers = {k.lower(): v.lower() for k, v in resp.headers.items()}

        for header_name, tech_map in HEADER_TECH_MAP.items():
            header_val = headers.get(header_name, "")
            for pattern, (tech_name, category) in tech_map.items():
                if pattern in header_val:
                    stack.all_techs[tech_name] = category
                    if category == "server":
                        stack.server = tech_name
                        # Extract version
                        ver_match = re.search(r"[\d.]+", header_val)
                        if ver_match:
                            stack.server_version = ver_match.group()
                    elif category == "language":
                        stack.language = tech_name
                    elif category == "framework":
                        stack.framework = tech_name
                    elif category == "cms":
                        stack.cms = tech_name
                    elif category == "cdn":
                        stack.cdn = tech_name

    def _check_cookies(self, resp, stack: TechStack):
        """Check cookies for technology signatures."""
        if not hasattr(resp, "cookies"):
            return
        for cookie_name in resp.cookies.keys():
            cookie_lower = cookie_name.lower()
            for pattern, (tech_name, category) in COOKIE_TECH_MAP.items():
                if pattern in cookie_lower:
                    stack.all_techs[tech_name] = category
                    if category == "language" and not stack.language:
                        stack.language = tech_name
                    elif category == "framework" and not stack.framework:
                        stack.framework = tech_name

    def _check_body(self, body: str, stack: TechStack):
        """Check response body for technology patterns."""
        if not body:
            return
        body_lower = body[:50000].lower()  # limit scan to first 50KB

        for pattern, tech_name, category in HTML_TECH_PATTERNS:
            match = re.search(pattern, body_lower, re.IGNORECASE)
            if match:
                stack.all_techs[tech_name] = category
                if category == "cms" and not stack.cms:
                    stack.cms = tech_name
                    if match.lastindex and match.group(1):
                        stack.cms_version = match.group(1)
                elif category == "js_framework" and tech_name not in stack.js_frameworks:
                    stack.js_frameworks.append(tech_name)

        for pattern, (tech_name, category) in CSS_CLASS_PATTERNS.items():
            if re.search(pattern, body_lower, re.IGNORECASE):
                stack.all_techs[tech_name] = category
                if category == "cms" and not stack.cms:
                    stack.cms = tech_name


# ── CVEMatcher ─────────────────────────────────────────────────────────


class CVEMatcher:
    """Match detected technologies against known CVEs."""

    def __init__(self, engine):
        self.engine = engine
        self.verbose = engine.config.get("verbose", False)
        self._min_cvss = engine.config.get("min_cve_cvss", 7.0)

    def run(self, tech_stack: TechStack) -> List[CVEMatch]:
        """Match TechStack against CVE database."""
        matches = []
        all_tech_names = set()

        # Collect all detected tech names (lowercase)
        if tech_stack:
            for name in tech_stack.all_techs:
                all_tech_names.add(name.lower())
            if tech_stack.cms:
                all_tech_names.add(tech_stack.cms.lower())
            if tech_stack.server:
                all_tech_names.add(tech_stack.server.lower())
            if tech_stack.framework:
                all_tech_names.add(tech_stack.framework.lower())
            if tech_stack.language:
                all_tech_names.add(tech_stack.language.lower())

        for cve in CVE_DATABASE:
            cve_tech = cve["tech"].lower()
            # Check if any detected tech matches the CVE tech
            if any(cve_tech in tech or tech in cve_tech for tech in all_tech_names):
                if cve["cvss"] >= self._min_cvss:
                    matches.append(
                        CVEMatch(
                            cve_id=cve["cve_id"],
                            description=cve["description"],
                            cvss=cve["cvss"],
                            tech=cve["tech"],
                            endpoint_hint=cve.get("endpoint_hint", ""),
                        )
                    )

        if self.verbose and matches:
            print(f"{Colors.info(f'CVE matches: {len(matches)} CVEs (CVSS >= {self._min_cvss})')}")

        return matches


# ── Main Enricher ──────────────────────────────────────────────────────


class IntelligenceEnricher:
    """Phase 6 — Aggregate intelligence from all sources."""

    def __init__(self, engine):
        self.engine = engine
        self.verbose = engine.config.get("verbose", False)
        self.fingerprinter = TechFingerprinter(engine)
        self.cve_matcher = CVEMatcher(engine)

    def run(self, responses: List = None, params: List = None, urls: Set = None) -> IntelligenceBundle:
        """Run all enrichment steps and return IntelligenceBundle."""
        self.engine.emit_pipeline_event("phase6_start", {})
        bundle = IntelligenceBundle()

        # Tech fingerprinting
        if responses:
            bundle.tech_stack = self.fingerprinter.run(responses)
        else:
            bundle.tech_stack = TechStack()

        # CVE matching
        bundle.cve_matches = self.cve_matcher.run(bundle.tech_stack)

        # Param context enrichment
        if params:
            bundle.param_weights = self._enrich_params(params)

        # Endpoint type classification
        if urls:
            bundle.endpoint_types = self._classify_endpoints(urls)

        self.engine.emit_pipeline_event("phase6_complete", bundle.to_dict())
        if self.verbose:
            msg = (
                f"Intelligence enrichment complete: {len(bundle.cve_matches)} CVEs, "
                f"{len(bundle.param_weights)} weighted params"
            )
            print(Colors.info(msg))

        return bundle

    def _enrich_params(self, params: List) -> Dict[str, float]:
        """Assign context weights to parameters."""
        weights = {}
        for param_entry in params:
            # param_entry is typically (url, method, name, value, source)
            if isinstance(param_entry, (list, tuple)) and len(param_entry) >= 3:
                param_name = param_entry[2]
            elif isinstance(param_entry, dict):
                param_name = param_entry.get("param", "")
            else:
                continue

            if not param_name:
                continue

            best_weight = 0.5  # default weight
            for context_type, rule in PARAM_CONTEXT_WEIGHTS.items():
                for pattern in rule["patterns"]:
                    if re.match(pattern, param_name):
                        best_weight = max(best_weight, rule["weight"])
                        break

            weights[param_name] = best_weight

        return weights

    def _classify_endpoints(self, urls: Set) -> Dict[str, str]:
        """Classify endpoint types."""
        endpoint_types = {}
        for url in urls:
            endpoint_types[url] = self._classify_single_endpoint(url)
        return endpoint_types

    @staticmethod
    def _classify_single_endpoint(url: str) -> str:
        """Classify a single URL into an endpoint type."""
        path = urlparse(url).path.lower()

        # Login / Auth endpoints
        if any(kw in path for kw in ["login", "signin", "auth", "oauth", "sso", "register", "signup"]):
            return "LOGIN"

        # Admin endpoints
        if any(kw in path for kw in ["admin", "dashboard", "panel", "manage", "console"]):
            return "ADMIN"

        # Upload endpoints
        if any(kw in path for kw in ["upload", "import", "attach", "file"]):
            return "UPLOAD"

        # API endpoints
        if any(kw in path for kw in ["/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/"]):
            return "API"

        # Form / user input endpoints
        if any(kw in path for kw in ["search", "comment", "contact", "feedback", "form", "submit"]):
            return "FORM"

        # Static assets
        from core.passive_recon import URLDeduplicator

        if URLDeduplicator.is_static(url):
            return "STATIC"

        return "UNKNOWN"
