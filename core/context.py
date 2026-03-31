#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v8.0 - ULTIMATE EDITION
Context Intelligence Module

Analyzes user-controlled inputs and their behavior context to predict
which vulnerability types are most likely. Assigns context weights
used by the prioritizer and adaptive testing engine.
"""

import os
import sys
import re
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Colors

# Maps context hints to predicted vulnerability types with base weight
CONTEXT_RULES = {
    'sqli': {
        'param_patterns': [
            r'(?i)(id|user_?id|item_?id|product_?id|cat_?id|order_?id|page|num|count)',
            r'(?i)(sort|order|group|column|table|field|key)',
            r'(?i)(search|query|q|keyword|filter|where)',
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


class ContextIntelligence:
    """Analyzes inputs and endpoints to predict vulnerability context."""

    def __init__(self, engine):
        self.engine = engine
        self.verbose = engine.config.get('verbose', False)

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

    def analyze_parameters(self, parameters):
        """Analyze all parameters and return enriched parameter list.

        Each parameter tuple is extended with context predictions and
        inferred input type.  Returns a list of dicts.
        """
        enriched = []
        for param_url, method, param_name, param_value, source in parameters:
            predictions = self.analyze_input(param_url, method, param_name, param_value, source)
            input_type = self.infer_input_type(param_value)

            enriched.append({
                'url': param_url,
                'method': method,
                'param': param_name,
                'value': param_value,
                'source': source,
                'input_type': input_type,
                'predictions': predictions,
            })

        if self.verbose and enriched:
            high_count = sum(
                1 for e in enriched
                if any(w >= 0.4 for w in e['predictions'].values())
            )
            print(f"{Colors.info(f'Context analysis: {len(enriched)} inputs, {high_count} with high-confidence predictions')}")

        return enriched

    def get_recommended_modules(self, enriched_param):
        """Given an enriched parameter, return recommended module keys sorted by weight."""
        predictions = enriched_param.get('predictions', {})
        sorted_vulns = sorted(predictions.items(), key=lambda x: x[1], reverse=True)
        return [(vuln, weight) for vuln, weight in sorted_vulns if weight > 0]
