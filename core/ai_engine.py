#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v8.0 - ULTIMATE EDITION
AI Intelligence Engine

Pattern-based vulnerability prediction, smart payload selection,
anomaly detection, and adaptive attack strategy using statistical
learning and heuristic models.
"""

import os
import json
import math
import time
import random
import hashlib
from collections import defaultdict


from config import Config, Colors

# Anomaly detection thresholds
MIN_BASELINE_TIME = 0.001
AI_DATA_FILE = os.path.join(Config.BASE_DIR, '.atomic_ai_data.json')

# Feature weights for vulnerability prediction
VULN_FEATURE_WEIGHTS = {
    'sqli': {
        'param_numeric': 0.7, 'param_id': 0.8, 'param_search': 0.6,
        'endpoint_api': 0.5, 'endpoint_auth': 0.7, 'has_db_hints': 0.9,
        'tech_php': 0.6, 'tech_asp': 0.7, 'tech_java': 0.5,
    },
    'xss': {
        'param_string': 0.7, 'param_search': 0.8, 'param_name': 0.6,
        'endpoint_search': 0.7, 'endpoint_comment': 0.8, 'reflects_input': 0.9,
        'tech_php': 0.5, 'tech_node': 0.6,
    },
    'lfi': {
        'param_file': 0.9, 'param_path': 0.9, 'param_page': 0.8,
        'param_include': 0.9, 'endpoint_download': 0.8, 'tech_php': 0.8,
    },
    'cmdi': {
        'param_cmd': 0.9, 'param_exec': 0.9, 'param_ping': 0.8,
        'param_ip': 0.7, 'endpoint_admin': 0.6, 'tech_php': 0.6,
        'tech_python': 0.5,
    },
    'ssrf': {
        'param_url': 0.9, 'param_redirect': 0.8, 'param_callback': 0.8,
        'param_dest': 0.7, 'endpoint_api': 0.6, 'tech_java': 0.6,
        'tech_node': 0.6,
    },
    'ssti': {
        'param_template': 0.9, 'param_name': 0.5, 'param_message': 0.6,
        'reflects_input': 0.7, 'tech_python': 0.8, 'tech_java': 0.6,
        'tech_php': 0.5,
    },
}

# Param name patterns mapped to feature keys
PARAM_FEATURES = {
    'param_numeric': lambda v: v.isdigit() if v else False,
    'param_id': lambda n: any(k in n.lower() for k in ['id', 'uid', 'user_id', 'pid', 'item_id']),
    'param_search': lambda n: any(k in n.lower() for k in ['search', 'q', 'query', 'keyword', 'term']),
    'param_string': lambda v: bool(v) and not v.isdigit(),
    'param_name': lambda n: any(k in n.lower() for k in ['name', 'user', 'title', 'comment', 'msg']),
    'param_file': lambda n: any(k in n.lower() for k in ['file', 'filename', 'document', 'attachment']),
    'param_path': lambda n: any(k in n.lower() for k in ['path', 'dir', 'folder', 'filepath']),
    'param_page': lambda n: any(k in n.lower() for k in ['page', 'view', 'template', 'include', 'load']),
    'param_include': lambda n: any(k in n.lower() for k in ['include', 'require', 'src', 'source']),
    'param_cmd': lambda n: any(k in n.lower() for k in ['cmd', 'command', 'exec', 'run', 'system']),
    'param_exec': lambda n: any(k in n.lower() for k in ['execute', 'shell', 'process']),
    'param_ping': lambda n: any(k in n.lower() for k in ['ping', 'host', 'target', 'address']),
    'param_ip': lambda n: any(k in n.lower() for k in ['ip', 'addr', 'server', 'hostname']),
    'param_url': lambda n: any(k in n.lower() for k in ['url', 'uri', 'link', 'href', 'redirect']),
    'param_redirect': lambda n: any(k in n.lower() for k in ['redirect', 'return', 'next', 'goto', 'rurl']),
    'param_callback': lambda n: any(k in n.lower() for k in ['callback', 'webhook', 'endpoint', 'api_url']),
    'param_dest': lambda n: any(k in n.lower() for k in ['dest', 'destination', 'forward', 'proxy']),
    'param_template': lambda n: any(k in n.lower() for k in ['template', 'tpl', 'layout', 'render']),
    'param_message': lambda n: any(k in n.lower() for k in ['message', 'body', 'content', 'text', 'data']),
}

# Endpoint patterns
ENDPOINT_FEATURES = {
    'endpoint_api': lambda u: '/api/' in u.lower() or '/rest/' in u.lower(),
    'endpoint_auth': lambda u: any(k in u.lower() for k in ['/login', '/auth', '/signin', '/register']),
    'endpoint_search': lambda u: any(k in u.lower() for k in ['/search', '/find', '/query', '/filter']),
    'endpoint_comment': lambda u: any(k in u.lower() for k in ['/comment', '/review', '/feedback', '/post']),
    'endpoint_download': lambda u: any(k in u.lower() for k in ['/download', '/file', '/export', '/read']),
    'endpoint_admin': lambda u: any(k in u.lower() for k in ['/admin', '/manage', '/dashboard', '/panel']),
}


class AIEngine:
    """AI-powered intelligence engine for smart scanning decisions."""

    def __init__(self, engine):
        self.engine = engine
        self.verbose = engine.config.get('verbose', False)

        # Historical data
        self.vuln_history = defaultdict(lambda: defaultdict(int))
        self.payload_effectiveness = defaultdict(lambda: defaultdict(float))
        self.endpoint_risk_cache = {}
        self.target_profile = {}

        # Real-time state
        self.response_anomalies = []
        self.successful_techniques = []
        self.failed_attempts = defaultdict(int)

        self._load()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self):
        """Load AI data from disk."""
        if not os.path.isfile(AI_DATA_FILE):
            return
        try:
            with open(AI_DATA_FILE, 'r') as f:
                data = json.load(f)
            for vuln, params in data.get('vuln_history', {}).items():
                for param, count in params.items():
                    self.vuln_history[vuln][param] = count
            for vuln, payloads in data.get('payload_effectiveness', {}).items():
                for payload, score in payloads.items():
                    self.payload_effectiveness[vuln][payload] = score
            if self.verbose:
                total = sum(sum(v.values()) for v in self.vuln_history.values())
                print(f"{Colors.info(f'AI Engine loaded {total} historical patterns')}")
        except Exception:
            pass

    def save(self):
        """Persist AI data to disk."""
        data = {
            'vuln_history': {k: dict(v) for k, v in self.vuln_history.items()},
            'payload_effectiveness': {k: dict(v) for k, v in self.payload_effectiveness.items()},
            'updated': time.time(),
        }
        try:
            with open(AI_DATA_FILE, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Vulnerability Prediction
    # ------------------------------------------------------------------

    def predict_vulnerabilities(self, url, param_name, param_value):
        """Predict likely vulnerability types for a parameter.

        Returns a sorted list of (vuln_type, probability) tuples.
        """
        features = self._extract_features(url, param_name, param_value)
        predictions = {}

        for vuln_type, weight_map in VULN_FEATURE_WEIGHTS.items():
            score = 0.0
            active_features = 0
            for feature_key, weight in weight_map.items():
                if features.get(feature_key, False):
                    score += weight
                    active_features += 1

            # Normalize to 0-1 range
            max_possible = sum(weight_map.values())
            probability = score / max_possible if max_possible > 0 else 0

            # Boost from historical data
            history_boost = self._get_history_boost(vuln_type, param_name)
            probability = min(1.0, probability + history_boost)

            if probability > 0.1:
                predictions[vuln_type] = round(probability, 3)

        return sorted(predictions.items(), key=lambda x: -x[1])

    def _extract_features(self, url, param_name, param_value):
        """Extract feature vector from URL, param name, and value."""
        features = {}

        # Param-based features
        for feat_key, check_fn in PARAM_FEATURES.items():
            if 'param_' in feat_key and feat_key.endswith(('numeric', 'string')):
                features[feat_key] = check_fn(param_value)
            else:
                features[feat_key] = check_fn(param_name)

        # Endpoint-based features
        for feat_key, check_fn in ENDPOINT_FEATURES.items():
            features[feat_key] = check_fn(url)

        # Tech-based features from context intelligence
        detected_tech = getattr(self.engine, 'context', None)
        if detected_tech and hasattr(detected_tech, 'detected_tech'):
            tech_set = detected_tech.detected_tech
            features['tech_php'] = 'php' in str(tech_set).lower()
            features['tech_asp'] = 'asp' in str(tech_set).lower()
            features['tech_java'] = 'java' in str(tech_set).lower()
            features['tech_node'] = 'node' in str(tech_set).lower()
            features['tech_python'] = 'python' in str(tech_set).lower()

        # DB hints
        features['has_db_hints'] = any(
            k in param_name.lower()
            for k in ['id', 'uid', 'sort', 'order', 'column', 'table', 'db']
        )

        # Reflection likelihood (heuristic)
        features['reflects_input'] = any(
            k in param_name.lower()
            for k in ['search', 'q', 'query', 'name', 'msg', 'comment', 'title']
        )

        return features

    def _get_history_boost(self, vuln_type, param_name):
        """Get probability boost from historical vulnerability data."""
        history = self.vuln_history.get(vuln_type, {})
        if not history:
            return 0.0

        # Check if this param pattern was vulnerable before
        param_lower = param_name.lower()
        total_hits = sum(history.values())
        param_hits = sum(
            count for pattern, count in history.items()
            if pattern.lower() in param_lower or param_lower in pattern.lower()
        )
        if total_hits == 0:
            return 0.0
        return min(0.2, (param_hits / total_hits) * 0.3)

    # ------------------------------------------------------------------
    # Smart Payload Selection
    # ------------------------------------------------------------------

    def get_smart_payloads(self, vuln_type, all_payloads, param_name='', max_payloads=None):
        """Reorder payloads based on AI-predicted effectiveness.

        Combines historical success rates with parameter-specific heuristics.
        """
        effectiveness = self.payload_effectiveness.get(vuln_type, {})

        def score_payload(payload):
            # Historical effectiveness score
            hist_score = effectiveness.get(payload, 0.5)

            # Length penalty: shorter payloads less likely to be blocked
            length_penalty = max(0, 1.0 - (len(payload) / 500))

            # Param-specific bonus
            param_bonus = 0.0
            param_lower = param_name.lower()
            if vuln_type == 'sqli' and any(k in param_lower for k in ['id', 'uid', 'sort']):
                if 'UNION' in payload.upper() or 'OR' in payload.upper():
                    param_bonus = 0.1
            elif vuln_type == 'xss' and any(k in param_lower for k in ['search', 'q', 'name']):
                if '<script>' in payload.lower() or 'onerror' in payload.lower():
                    param_bonus = 0.1
            elif vuln_type == 'lfi' and any(k in param_lower for k in ['file', 'path', 'page']):
                if 'etc/passwd' in payload or 'php://filter' in payload:
                    param_bonus = 0.15

            return -(hist_score * 0.6 + length_penalty * 0.2 + param_bonus * 0.2)

        sorted_payloads = sorted(all_payloads, key=score_payload)
        if max_payloads:
            return sorted_payloads[:max_payloads]
        return sorted_payloads

    # ------------------------------------------------------------------
    # Anomaly Detection
    # ------------------------------------------------------------------

    def detect_anomaly(self, baseline_time, response_time, baseline_length,
                       response_length, baseline_status, response_status):
        """Detect anomalies in response patterns using statistical analysis.

        Returns an anomaly score between 0.0 (normal) and 1.0 (highly anomalous).
        """
        scores = []

        # Timing anomaly (z-score based)
        if baseline_time > 0:
            time_deviation = abs(response_time - baseline_time) / max(baseline_time, MIN_BASELINE_TIME)
            time_score = min(1.0, time_deviation / 3.0)
            scores.append(time_score * 0.4)

        # Length anomaly
        if baseline_length > 0:
            length_deviation = abs(response_length - baseline_length) / max(baseline_length, 1)
            length_score = min(1.0, length_deviation / LENGTH_DEVIATION_THRESHOLD)
            scores.append(length_score * 0.3)

        # Status code anomaly
        if baseline_status != response_status:
            status_score = 0.8 if response_status >= 500 else 0.5
            scores.append(status_score * 0.3)
        else:
            scores.append(0.0)

        return sum(scores)

    # ------------------------------------------------------------------
    # Attack Strategy
    # ------------------------------------------------------------------

    def get_attack_strategy(self, url, parameters):
        """Determine optimal attack strategy for a target.

        Returns a dict with recommended module order, payload limits, and
        evasion level.
        """
        strategy = {
            'module_order': [],
            'payload_limit': None,
            'evasion_recommendation': 'none',
            'aggressive': False,
        }

        # Predict vulnerabilities for each parameter
        vuln_scores = defaultdict(float)
        for param in parameters:
            if isinstance(param, dict):
                pname = param.get('param', '')
                pvalue = param.get('value', '')
                purl = param.get('url', url)
            elif isinstance(param, (list, tuple)) and len(param) >= 4:
                purl, _, pname, pvalue = param[0], param[1], param[2], param[3]
            else:
                continue

            predictions = self.predict_vulnerabilities(purl, pname, pvalue)
            for vuln_type, prob in predictions:
                vuln_scores[vuln_type] = max(vuln_scores[vuln_type], prob)

        # Sort modules by predicted probability
        strategy['module_order'] = sorted(
            vuln_scores.keys(), key=lambda k: -vuln_scores[k]
        )

        # WAF detection → recommend evasion
        if hasattr(self.engine, 'adaptive') and self.engine.adaptive.waf_detected:
            strategy['evasion_recommendation'] = 'high'
            strategy['payload_limit'] = 15

        # High signal strength → go aggressive
        if hasattr(self.engine, 'adaptive') and self.engine.adaptive.signal_strength > 0.5:
            strategy['aggressive'] = True

        return strategy

    # ------------------------------------------------------------------
    # Learning (called after findings)
    # ------------------------------------------------------------------

    def record_finding(self, technique, param_name, payload):
        """Record a successful finding for AI learning."""
        vuln_type = self._technique_to_type(technique)
        self.vuln_history[vuln_type][param_name] += 1
        self.payload_effectiveness[vuln_type][payload] = min(
            1.0,
            self.payload_effectiveness[vuln_type].get(payload, 0.5) + 0.1,
        )
        self.successful_techniques.append(vuln_type)

    def record_failure(self, technique, payload):
        """Record a failed attempt for AI learning."""
        vuln_type = self._technique_to_type(technique)
        self.payload_effectiveness[vuln_type][payload] = max(
            0.0,
            self.payload_effectiveness[vuln_type].get(payload, 0.5) - 0.05,
        )
        self.failed_attempts[vuln_type] += 1

    def _technique_to_type(self, technique):
        """Map technique name to vulnerability type key."""
        technique_lower = technique.lower()
        mapping = {
            'sql': 'sqli', 'xss': 'xss', 'lfi': 'lfi', 'rfi': 'lfi',
            'command': 'cmdi', 'ssrf': 'ssrf', 'ssti': 'ssti',
            'xxe': 'xxe', 'idor': 'idor', 'cors': 'cors',
            'jwt': 'jwt', 'nosql': 'nosql', 'upload': 'upload',
            'redirect': 'open_redirect', 'crlf': 'crlf', 'hpp': 'hpp',
        }
        for key, vuln_type in mapping.items():
            if key in technique_lower:
                return vuln_type
        return 'unknown'

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def get_ai_summary(self):
        """Return a summary of AI engine state."""
        return {
            'total_patterns': sum(
                sum(v.values()) for v in self.vuln_history.values()
            ),
            'successful_techniques': len(self.successful_techniques),
            'failed_attempts': dict(self.failed_attempts),
            'anomalies_detected': len(self.response_anomalies),
        }
