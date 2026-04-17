#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v10.0 - ULTIMATE EDITION
Risk-Based Prioritization Engine

Scores endpoints by type and context, builds a priority queue so the
scanner processes the highest-value targets first.

Priority tiers:
  - Authenticated endpoints → HIGH
  - File uploads → HIGH
  - API / admin endpoints → HIGH
  - Public static pages → LOW
"""

import re
from urllib.parse import urlparse


from config import Colors

# Static patterns → priority boost
HIGH_PRIORITY_PATTERNS = [
    (r'(?i)(login|signin|auth|oauth|sso|token|session)', 0.9, 'auth'),
    (r'(?i)(admin|dashboard|manage|control|panel|settings)', 0.85, 'admin'),
    (r'(?i)/api/', 0.8, 'api'),
    (r'(?i)(upload|import|file|attach|media)', 0.8, 'upload'),
    (r'(?i)(payment|checkout|billing|order|cart|purchase)', 0.75, 'payment'),
    (r'(?i)(user|profile|account|member)', 0.7, 'user'),
    (r'(?i)(search|query|filter|find)', 0.65, 'search'),
    (r'(?i)(comment|review|feedback|contact|message)', 0.6, 'input'),
    (r'(?i)(download|export|report|pdf)', 0.55, 'download'),
    (r'(?i)(graphql|rest|v\d+/)', 0.7, 'api'),
    # v10.0 additions
    (r'(?i)(webhook|callback|notify|hook)', 0.75, 'webhook'),
    (r'(?i)(reset|forgot|recover|password)', 0.85, 'password_reset'),
    (r'(?i)(invite|register|signup|onboard)', 0.7, 'registration'),
    (r'(?i)(config|setup|install|debug)', 0.8, 'configuration'),
    (r'(?i)(ws|socket|realtime|stream)', 0.65, 'websocket'),
    (r'(?i)(internal|private|staging|dev)', 0.8, 'internal'),
]

LOW_PRIORITY_PATTERNS = [
    (r'(?i)\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|ttf|eot)(\?|$)', -0.5, 'static_asset'),
    (r'(?i)(static|assets|images|fonts|vendor|lib)', -0.4, 'static_dir'),
    (r'(?i)(about|privacy|terms|faq|help|sitemap|robots)', -0.3, 'informational'),
]

# Minimum score below which endpoints are skipped entirely
SKIP_THRESHOLD = 0.15


class EndpointPrioritizer:
    """Scores and ranks endpoints for scan priority."""

    def __init__(self, engine):
        self.engine = engine
        self.verbose = engine.config.get('verbose', False)

        # Load keyword buckets from rules engine when available
        rules = getattr(engine, 'rules', None)
        self._keyword_buckets = {}
        self._priority_order = []
        if rules:
            self._keyword_buckets = rules.get_keyword_buckets()
            self._priority_order = rules.get_priority_order()

    def score_endpoint(self, url, method='GET', param='', source=''):
        """Compute priority score for a single endpoint (0.0-1.0)."""
        score = 0.5  # neutral base
        path = urlparse(url).path + '?' + (urlparse(url).query or '')

        # Rules-engine keyword buckets (YAML-defined priorities)
        if self._keyword_buckets and self._priority_order:
            path_lower = path.lower()
            param_lower = param.lower() if param else ''
            for bucket_idx, bucket_name in enumerate(self._priority_order):
                keywords = self._keyword_buckets.get(bucket_name, [])
                for keyword in keywords:
                    if keyword.lower() in path_lower or keyword.lower() in param_lower:
                        # Higher priority buckets (earlier in order) get higher scores
                        bucket_score = 0.95 - (bucket_idx * 0.05)
                        score = max(score, max(0.5, bucket_score))
                        break

        # High-priority patterns (hardcoded fallback)
        for pattern, boost, tag in HIGH_PRIORITY_PATTERNS:
            if re.search(pattern, path):
                score = max(score, boost)

        # Low-priority patterns
        for pattern, penalty, tag in LOW_PRIORITY_PATTERNS:
            if re.search(pattern, path):
                score += penalty

        # Boost for POST method
        if method.upper() == 'POST':
            score += 0.1

        # Boost for parameters from forms/API discovery
        source_boost = {
            'form': 0.1,
            'api': 0.15,
            'js_extracted': 0.1,
            'hidden_input': 0.1,
            'discovery': 0.05,
        }
        score += source_boost.get(source, 0.0)

        # Additional boost for authenticated context (param hints)
        auth_params = re.compile(
            r'(?i)(token|session|auth|bearer|cookie|jwt|api_?key)',
        )
        if param and auth_params.search(param):
            score = max(score, 0.85)

        # Additional boost for file-upload context
        upload_params = re.compile(r'(?i)(file|upload|attachment|document|image)')
        if param and upload_params.search(param):
            score = max(score, 0.8)

        return max(0.0, min(1.0, score))

    def prioritize_parameters(self, enriched_params):
        """Sort enriched parameters by priority.

        *enriched_params*: list of dicts from ContextIntelligence.analyze_parameters().
        Returns the list sorted HIGH → LOW priority with a 'priority' key added.
        Low-value endpoints below SKIP_THRESHOLD are removed.
        """
        scored = []
        skipped = 0

        for ep in enriched_params:
            base_score = self.score_endpoint(
                ep['url'], ep['method'], ep['param'], ep['source'],
            )
            # Combine with context prediction strength
            max_prediction = max(ep.get('predictions', {}).values(), default=0)
            combined = 0.6 * base_score + 0.4 * max_prediction
            ep['priority'] = round(combined, 3)

            if ep['priority'] >= SKIP_THRESHOLD:
                scored.append(ep)
            else:
                skipped += 1

        scored.sort(key=lambda x: x['priority'], reverse=True)

        if self.verbose:
            high = sum(1 for p in scored if p['priority'] >= 0.7)
            med = sum(1 for p in scored if 0.4 <= p['priority'] < 0.7)
            low = sum(1 for p in scored if p['priority'] < 0.4)
            print(f"{Colors.info(f'Priority queue: {high} HIGH, {med} MEDIUM, {low} LOW (skipped {skipped})')}")

        return scored

    def prioritize_urls(self, urls):
        """Sort plain URL set by priority. Returns list of (url, score).

        Filters out URLs below SKIP_THRESHOLD.
        """
        scored = [(url, self.score_endpoint(url)) for url in urls]
        scored = [(u, s) for u, s in scored if s >= SKIP_THRESHOLD]
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored
