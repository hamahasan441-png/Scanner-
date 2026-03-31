#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v8.0 - ULTIMATE EDITION
Endpoint Prioritization Module

Scores endpoints by type and context, builds a priority queue so the
scanner processes the highest-value targets first.
"""

import os
import sys
import re
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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
]

LOW_PRIORITY_PATTERNS = [
    (r'(?i)\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|ttf|eot)(\?|$)', -0.5, 'static_asset'),
    (r'(?i)(static|assets|images|fonts|vendor|lib)', -0.4, 'static_dir'),
    (r'(?i)(about|privacy|terms|faq|help|sitemap|robots)', -0.3, 'informational'),
]


class EndpointPrioritizer:
    """Scores and ranks endpoints for scan priority."""

    def __init__(self, engine):
        self.engine = engine
        self.verbose = engine.config.get('verbose', False)

    def score_endpoint(self, url, method='GET', param='', source=''):
        """Compute priority score for a single endpoint (0.0-1.0)."""
        score = 0.5  # neutral base
        path = urlparse(url).path + '?' + (urlparse(url).query or '')

        # High-priority patterns
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

        return max(0.0, min(1.0, score))

    def prioritize_parameters(self, enriched_params):
        """Sort enriched parameters by priority.

        *enriched_params*: list of dicts from ContextIntelligence.analyze_parameters().
        Returns the list sorted HIGH → LOW priority with a 'priority' key added.
        """
        for ep in enriched_params:
            base_score = self.score_endpoint(
                ep['url'], ep['method'], ep['param'], ep['source'],
            )
            # Combine with context prediction strength
            max_prediction = max(ep.get('predictions', {}).values(), default=0)
            combined = 0.6 * base_score + 0.4 * max_prediction
            ep['priority'] = round(combined, 3)

        enriched_params.sort(key=lambda x: x['priority'], reverse=True)

        if self.verbose and enriched_params:
            high = sum(1 for p in enriched_params if p['priority'] >= 0.7)
            med = sum(1 for p in enriched_params if 0.4 <= p['priority'] < 0.7)
            low = sum(1 for p in enriched_params if p['priority'] < 0.4)
            print(f"{Colors.info(f'Priority queue: {high} HIGH, {med} MEDIUM, {low} LOW')}")

        return enriched_params

    def prioritize_urls(self, urls):
        """Sort plain URL set by priority. Returns list of (url, score)."""
        scored = [(url, self.score_endpoint(url)) for url in urls]
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored
