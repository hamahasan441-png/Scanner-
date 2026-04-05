#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v9.0 - ULTIMATE EDITION
Context Intelligence Module

Analyzes user-controlled inputs and their behavior context to predict
which vulnerability types are most likely. Assigns context weights
used by the prioritizer and adaptive testing engine.

Responsibilities:
  - Extract and classify user-controllable inputs
  - Analyze how inputs are processed (reflected, DB, system call, URL fetch)
  - Perform tech fingerprinting to tailor payloads
  - Filter out static endpoints without parameters
  - Ignore non-controllable inputs
"""

import re
from urllib.parse import urlparse, parse_qs


from config import Colors

# Maps context hints to predicted vulnerability types with base weight
CONTEXT_RULES = {
    'sqli': {
        'param_patterns': [
            r'(?i)(id|user_?id|item_?id|product_?id|cat_?id|order_?id|page|num|count)',
            r'(?i)(sort|order|group|column|table|field|key)',
            r'(?i)(search|query|q|keyword|filter|where)',
            r'path\[\d+\]',  # Numeric path segments (REST IDs)
        ],
        'value_patterns': [r'^\d+$', r'^\w+$'],
        'endpoint_patterns': [
            r'(?i)(search|query|filter|list|view|detail|show|get|fetch)',
            r'(?i)(product|item|user|order|article|post|comment)',
        ],
        'content_hints': ['database', 'sql', 'mysql', 'query', 'select'],
    },
    'xss': {
        'param_patterns': [
            r'(?i)(name|user|username|email|comment|message|title|body|text|content)',
            r'(?i)(search|q|query|keyword|input|value|data|callback)',
            r'(?i)(redirect|url|next|return|ref|page)',
        ],
        'value_patterns': [r'.*[<>\'"&].*', r'^https?://'],
        'endpoint_patterns': [
            r'(?i)(search|comment|profile|post|message|feedback|contact|form)',
        ],
        'content_hints': ['html', 'render', 'template', 'display', 'output'],
    },
    'lfi': {
        'param_patterns': [
            r'(?i)(file|path|page|include|template|dir|document|folder|root)',
            r'(?i)(load|read|open|resource|src|source|conf|config)',
            r'(?i)(lang|language|locale|theme|style|view|layout)',
        ],
        'value_patterns': [r'.*[\\/].*', r'.*\.[\w]+$'],
        'endpoint_patterns': [
            r'(?i)(download|file|include|load|read|view|display)',
        ],
        'content_hints': ['file', 'path', 'include', 'require', 'fopen'],
    },
    'ssrf': {
        'param_patterns': [
            r'(?i)(url|uri|link|href|src|source|dest|target|proxy|feed)',
            r'(?i)(callback|webhook|redirect|fetch|load|remote|endpoint)',
            r'(?i)(api_?url|image_?url|pdf_?url|import_?url)',
        ],
        'value_patterns': [r'^https?://', r'^//'],
        'endpoint_patterns': [
            r'(?i)(fetch|proxy|import|webhook|callback|preview|check|validate)',
        ],
        'content_hints': ['url', 'fetch', 'request', 'curl', 'http'],
    },
    'cmdi': {
        'param_patterns': [
            r'(?i)(cmd|command|exec|run|shell|process|ping|host|ip|domain)',
            r'(?i)(daemon|upload|dir|log|operation|action|batch|job)',
        ],
        'value_patterns': [r'.*[;|&`$].*', r'^\d+\.\d+\.\d+\.\d+$'],
        'endpoint_patterns': [
            r'(?i)(ping|traceroute|nslookup|diagnostic|admin|system|exec|run)',
        ],
        'content_hints': ['exec', 'system', 'popen', 'shell', 'command'],
    },
    'ssti': {
        'param_patterns': [
            r'(?i)(template|name|user|email|message|greeting|preview|render)',
        ],
        'value_patterns': [r'.*[\{\}].*', r'.*\$\{.*\}.*'],
        'endpoint_patterns': [
            r'(?i)(template|render|preview|email|greeting|report)',
        ],
        'content_hints': ['template', 'jinja', 'twig', 'render', 'engine'],
    },
    'idor': {
        'param_patterns': [
            r'(?i)(id|user_?id|account_?id|profile_?id|order_?id|doc_?id)',
            r'(?i)(uid|pid|oid|ref|number|no|num)',
            r'path\[\d+\]',  # Numeric path segments (REST IDs)
        ],
        'value_patterns': [r'^\d+$', r'^[0-9a-f\-]+$'],
        'endpoint_patterns': [
            r'(?i)(profile|account|user|order|invoice|document|file|message)',
            r'/\d+(/|$)',
        ],
        'content_hints': ['user', 'account', 'profile', 'private'],
    },
    'nosql': {
        'param_patterns': [
            r'(?i)(user|username|login|password|email|search|query|filter)',
        ],
        'value_patterns': [r'.*[\{\}].*', r'.*\$.*'],
        'endpoint_patterns': [
            r'(?i)(api|login|auth|search|query|graphql)',
        ],
        'content_hints': ['mongo', 'nosql', 'json', 'bson', 'collection'],
    },
}

# Input type inference rules
INPUT_TYPE_RULES = [
    (r'^\d+$', 'int'),
    (r'^\d+\.\d+$', 'float'),
    (r'^https?://', 'url'),
    (r'^[\w.+-]+@[\w-]+\.[\w.]+$', 'email'),
    (r'^[0-9a-f\-]{8,}$', 'uuid'),
    (r'^/[\w/.\-]+$', 'path'),
    (r'.*\.(php|asp|jsp|html|txt|pdf|jpg|png)$', 'file'),
    (r'.*', 'string'),
]

# Context weight increments per signal type
WEIGHT_PARAM_MATCH = 0.3
WEIGHT_VALUE_MATCH = 0.2
WEIGHT_ENDPOINT_MATCH = 0.2
WEIGHT_RESPONSE_HINT = 0.15

# Static file extensions that should be skipped
STATIC_EXTENSIONS = re.compile(
    r'\.(?:css|js|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|mp[34]|avi|mov|pdf|zip|tar|gz)$',
    re.IGNORECASE,
)

# Non-controllable parameter names (framework-generated tokens)
NON_CONTROLLABLE_PARAMS = re.compile(
    r'^(?:__VIEWSTATE|__EVENTVALIDATION|__REQUESTDIGEST|csrf_token|_token|authenticity_token|__RequestVerificationToken)$',
    re.IGNORECASE,
)

# Technology fingerprint patterns (header/body hints → DB or framework)
TECH_FINGERPRINTS = {
    'mysql': re.compile(r'mysql|MariaDB', re.IGNORECASE),
    'postgresql': re.compile(r'postgresql|pgsql', re.IGNORECASE),
    'mssql': re.compile(r'Microsoft SQL|MSSQL|SQL\s*Server', re.IGNORECASE),
    'oracle': re.compile(r'Oracle|ORA-\d+', re.IGNORECASE),
    'sqlite': re.compile(r'sqlite', re.IGNORECASE),
    'mongodb': re.compile(r'mongo|bson', re.IGNORECASE),
    'php': re.compile(r'X-Powered-By:\s*PHP|\.php', re.IGNORECASE),
    'asp': re.compile(r'ASP\.NET|X-AspNet-Version', re.IGNORECASE),
    'django': re.compile(r'csrfmiddlewaretoken|django', re.IGNORECASE),
    'flask': re.compile(r'Werkzeug|flask', re.IGNORECASE),
    'express': re.compile(r'X-Powered-By:\s*Express', re.IGNORECASE),
    'java': re.compile(r'JSESSIONID|X-Powered-By:\s*Servlet', re.IGNORECASE),
}


class ContextIntelligence:
    """Analyzes inputs and endpoints to predict vulnerability context."""

    def __init__(self, engine):
        self.engine = engine
        self.verbose = engine.config.get('verbose', False)
        self.detected_tech = set()
        # Response fingerprint cache for pattern intelligence
        self._response_fingerprints = {}
        # Behavior patterns: param → observed behaviors
        self._behavior_patterns = {}

    # ------------------------------------------------------------------
    # Input filtering (§3 of the pipeline)
    # ------------------------------------------------------------------

    def is_static_endpoint(self, url):
        """Return True if the URL points to a static resource."""
        path = urlparse(url).path
        return bool(STATIC_EXTENSIONS.search(path))

    def is_controllable(self, param_name):
        """Return True if the parameter is user-controllable (not a framework token)."""
        if not param_name:
            return False
        return not NON_CONTROLLABLE_PARAMS.match(param_name)

    def should_skip(self, url, param_name, value, source):
        """Determine if a parameter should be skipped entirely.

        Filters:
          - Static endpoints without parameters
          - Non-controllable inputs (CSRF tokens, viewstate)
          - Empty param + empty value from non-form sources
        """
        # Static resource with no real parameter
        if self.is_static_endpoint(url) and not param_name:
            return True

        # Framework-generated tokens → not controllable
        if param_name and not self.is_controllable(param_name):
            return True

        # No parameter name AND no value → nothing to test
        if not param_name and not value and source not in ('form', 'api', 'api_extracted', 'path_param'):
            return True

        return False

    # ------------------------------------------------------------------
    # Tech fingerprinting (§4)
    # ------------------------------------------------------------------

    def fingerprint_response(self, response):
        """Analyze response headers and body for technology hints.

        Populates self.detected_tech.
        """
        if response is None:
            return

        combined = ''
        for k, v in response.headers.items():
            combined += f'{k}: {v}\n'
        combined += (response.text or '')[:3000]

        for tech_name, pattern in TECH_FINGERPRINTS.items():
            if pattern.search(combined):
                self.detected_tech.add(tech_name)

    def get_detected_tech(self):
        """Return the set of detected technologies."""
        return self.detected_tech

    # ------------------------------------------------------------------
    # Response-based context analysis (§4)
    # ------------------------------------------------------------------

    def analyze_response_context(self, url, param, value, response):
        """Check how the input is processed in the response.

        Returns a dict of context hints useful for selecting test branches.
        """
        hints = {
            'reflected': False,
            'in_db_context': False,
            'in_system_context': False,
            'in_url_fetch': False,
        }

        if response is None or not response.text:
            return hints

        body = response.text

        # Reflected → candidate for XSS / SSTI
        if value and value in body:
            hints['reflected'] = True

        # DB-related error strings → SQLi / NoSQL candidate
        db_patterns = ['sql', 'query', 'syntax', 'mysql', 'postgresql', 'oracle', 'mongo']
        body_lower = body.lower()
        if any(p in body_lower for p in db_patterns):
            hints['in_db_context'] = True

        # System call hints → Command Injection
        sys_patterns = ['sh:', 'bin/', 'command not found', 'permission denied', 'exec']
        if any(p in body_lower for p in sys_patterns):
            hints['in_system_context'] = True

        # URL fetch hints → SSRF
        url_patterns = ['could not connect', 'connection refused', 'timeout', 'dns', 'unreachable']
        if any(p in body_lower for p in url_patterns):
            hints['in_url_fetch'] = True

        return hints

    # ------------------------------------------------------------------
    # Core analysis (existing logic, improved)
    # ------------------------------------------------------------------

    def analyze_input(self, url, method, param, value, source=''):
        """Analyze a single input and return context predictions.

        Returns a dict mapping vulnerability type to a weight (0.0-1.0).
        """
        predictions = {}
        endpoint_path = urlparse(url).path.lower()

        for vuln_type, rules in CONTEXT_RULES.items():
            weight = 0.0

            # Check parameter name patterns
            for pattern in rules['param_patterns']:
                if param and re.search(pattern, param):
                    weight += WEIGHT_PARAM_MATCH
                    break

            # Check value patterns
            for pattern in rules['value_patterns']:
                if value and re.search(pattern, value):
                    weight += WEIGHT_VALUE_MATCH
                    break

            # Check endpoint path patterns
            for pattern in rules['endpoint_patterns']:
                if re.search(pattern, endpoint_path):
                    weight += WEIGHT_ENDPOINT_MATCH
                    break

            # Clamp weight to [0, 1]
            predictions[vuln_type] = min(weight, 1.0)

        return predictions

    def infer_input_type(self, value):
        """Infer the type of a user-controlled input value."""
        if not value:
            return 'string'
        for pattern, input_type in INPUT_TYPE_RULES:
            if re.match(pattern, value):
                return input_type
        return 'string'

    def classify_input(self, param, value, input_type):
        """Classify input based on usage context for vulnerability branch selection.

        Returns a list of candidate vulnerability types based on the input characteristics.
        """
        candidates = []
        if input_type in ('int', 'float'):
            candidates.append('sqli')
        if input_type == 'url':
            candidates.append('ssrf')
        if input_type == 'path' or input_type == 'file':
            candidates.append('lfi')

        # Check for reflected/command patterns in value
        if value:
            if re.search(r'[<>\'"&]', value):
                candidates.append('xss')
            if re.search(r'[;|&`$]', value):
                candidates.append('cmdi')

        return candidates

    def analyze_parameters(self, parameters):
        """Analyze all parameters and return enriched parameter list.

        Each parameter tuple is extended with context predictions,
        inferred input type, and classification.

        Filters out:
          - Static endpoints without parameters
          - Non-controllable inputs
        Returns a list of dicts.
        """
        enriched = []
        skipped = 0

        for param_url, method, param_name, param_value, source in parameters:
            # §3 Filter: skip static / non-controllable inputs
            if self.should_skip(param_url, param_name, param_value, source):
                skipped += 1
                continue

            predictions = self.analyze_input(param_url, method, param_name, param_value, source)
            input_type = self.infer_input_type(param_value)
            candidates = self.classify_input(param_name, param_value, input_type)

            enriched.append({
                'url': param_url,
                'method': method,
                'param': param_name,
                'value': param_value,
                'source': source,
                'input_type': input_type,
                'predictions': predictions,
                'candidates': candidates,
            })

        if self.verbose:
            high_count = sum(
                1 for e in enriched
                if any(w >= 0.4 for w in e['predictions'].values())
            )
            print(f"{Colors.info(f'Context analysis: {len(enriched)} inputs ({skipped} filtered), {high_count} with high-confidence predictions')}")
            if self.detected_tech:
                tech_list = ", ".join(sorted(self.detected_tech))
                print(f"{Colors.info(f'Detected tech: {tech_list}')}")

        return enriched

    def get_recommended_modules(self, enriched_param):
        """Given an enriched parameter, return recommended module keys sorted by weight."""
        predictions = enriched_param.get('predictions', {})
        sorted_vulns = sorted(predictions.items(), key=lambda x: x[1], reverse=True)
        return [(vuln, weight) for vuln, weight in sorted_vulns if weight > 0]

    # ------------------------------------------------------------------
    # Response Pattern Intelligence (§5)
    # ------------------------------------------------------------------

    def record_response_fingerprint(self, url, param, response):
        """Record response fingerprint for pattern-based intelligence."""
        if response is None:
            return

        key = f'{url}:{param}'
        fingerprint = {
            'status': response.status_code,
            'length': len(response.text or ''),
            'content_type': response.headers.get('Content-Type', ''),
            'has_error': any(
                p in (response.text or '').lower()[:2000]
                for p in ['error', 'exception', 'warning', 'fatal']
            ),
        }
        self._response_fingerprints[key] = fingerprint

    def get_response_pattern(self, url, param):
        """Return stored response fingerprint for a URL+param."""
        return self._response_fingerprints.get(f'{url}:{param}')

    def record_behavior(self, param, behavior_type, details=''):
        """Record observed behavior for a parameter.

        behavior_type: 'reflected', 'filtered', 'error_triggered', 'time_based', 'blocked'
        """
        behaviors = self._behavior_patterns.setdefault(param, [])
        behaviors.append({'type': behavior_type, 'details': details})

    def get_param_behaviors(self, param):
        """Return observed behaviors for a parameter."""
        return self._behavior_patterns.get(param, [])

    def get_tech_specific_recommendations(self):
        """Return vulnerability test recommendations based on detected tech stack.

        Maps detected technologies to most likely vulnerability types and
        recommended testing approaches.
        """
        recommendations = []

        tech_vuln_map = {
            'php': [('sqli', 'MySQL-focused SQLi'), ('lfi', 'PHP wrapper LFI'),
                    ('cmdi', 'PHP exec functions'), ('ssti', 'Twig/Smarty SSTI')],
            'asp': [('sqli', 'MSSQL-focused SQLi'), ('cmdi', 'PowerShell injection')],
            'django': [('ssti', 'Django template injection'), ('sqli', 'Django ORM bypass')],
            'flask': [('ssti', 'Jinja2 SSTI'), ('lfi', 'Flask debug mode')],
            'express': [('nosql', 'MongoDB injection'), ('ssti', 'EJS/Pug SSTI')],
            'java': [('ssti', 'Freemarker/Velocity SSTI'), ('sqli', 'JDBC injection'),
                     ('ssrf', 'Java URL class SSRF')],
            'mysql': [('sqli', 'MySQL-specific payloads')],
            'postgresql': [('sqli', 'PostgreSQL-specific payloads')],
            'mssql': [('sqli', 'MSSQL stacked queries & xp_cmdshell')],
            'mongodb': [('nosql', 'MongoDB operator injection')],
            'sqlite': [('sqli', 'SQLite-specific payloads')],
        }

        for tech in self.detected_tech:
            if tech in tech_vuln_map:
                for vuln_type, description in tech_vuln_map[tech]:
                    recommendations.append({
                        'tech': tech,
                        'vuln_type': vuln_type,
                        'description': description,
                    })

        return recommendations

    def get_intelligence_summary(self):
        """Return a summary of context intelligence state."""
        return {
            'detected_tech': list(self.detected_tech),
            'response_fingerprints': len(self._response_fingerprints),
            'behavior_patterns': len(self._behavior_patterns),
            'recommendations': len(self.get_tech_specific_recommendations()),
        }
