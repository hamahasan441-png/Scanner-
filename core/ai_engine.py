#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v8.0 - ULTIMATE EDITION
AI Intelligence Engine

Pattern-based vulnerability prediction, smart payload selection,
anomaly detection, adaptive attack strategy, vulnerability correlation,
exploit difficulty estimation, and confidence calibration using
statistical learning and heuristic models.
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
LENGTH_DEVIATION_THRESHOLD = 5.0
AI_DATA_FILE = os.path.join(Config.BASE_DIR, '.atomic_ai_data.json')

# Vulnerability correlation graph: (vuln_a, vuln_b) → chain label + severity boost
VULN_CORRELATIONS = {
    ('sqli', 'lfi'): {'chain': 'db_file_read', 'boost': 0.3, 'label': 'SQLi→LFI Chain'},
    ('sqli', 'cmdi'): {'chain': 'db_to_rce', 'boost': 0.4, 'label': 'SQLi→RCE Chain'},
    ('lfi', 'cmdi'): {'chain': 'file_to_rce', 'boost': 0.35, 'label': 'LFI→RCE Chain'},
    ('ssrf', 'lfi'): {'chain': 'ssrf_file_read', 'boost': 0.25, 'label': 'SSRF→File Read'},
    ('ssrf', 'cmdi'): {'chain': 'ssrf_to_rce', 'boost': 0.4, 'label': 'SSRF→RCE Chain'},
    ('ssti', 'cmdi'): {'chain': 'template_rce', 'boost': 0.45, 'label': 'SSTI→RCE Chain'},
    ('upload', 'cmdi'): {'chain': 'upload_rce', 'boost': 0.45, 'label': 'Upload→RCE Chain'},
    ('xss', 'sqli'): {'chain': 'xss_sqli', 'boost': 0.15, 'label': 'XSS→SQLi Pivot'},
    ('idor', 'sqli'): {'chain': 'idor_sqli', 'boost': 0.2, 'label': 'IDOR→SQLi Escalation'},
}

# Exploit difficulty factors per vulnerability type
EXPLOIT_DIFFICULTY = {
    'sqli': {'base': 0.3, 'factors': ['waf', 'parameterized', 'orm']},
    'xss': {'base': 0.2, 'factors': ['csp', 'sanitizer', 'httponly']},
    'lfi': {'base': 0.25, 'factors': ['chroot', 'realpath', 'waf']},
    'cmdi': {'base': 0.4, 'factors': ['sandbox', 'waf', 'allowlist']},
    'ssrf': {'base': 0.35, 'factors': ['allowlist', 'dns_rebind', 'network_segmentation']},
    'ssti': {'base': 0.45, 'factors': ['sandbox', 'restricted_env']},
    'xxe': {'base': 0.3, 'factors': ['dtd_disabled', 'parser_hardened']},
    'idor': {'base': 0.15, 'factors': ['uuid', 'authz_check']},
    'nosql': {'base': 0.3, 'factors': ['sanitizer', 'schema_validation']},
    'upload': {'base': 0.35, 'factors': ['extension_check', 'content_check', 'sandbox']},
    'cors': {'base': 0.2, 'factors': ['origin_check']},
    'jwt': {'base': 0.3, 'factors': ['algorithm_check', 'key_strength']},
}

# Tech-specific payload boost patterns
TECH_PAYLOAD_HINTS = {
    'php': {
        'sqli': ['mysql', 'mysqli', 'pdo'],
        'lfi': ['php://', 'expect://', 'data://', 'filter'],
        'cmdi': ['system', 'exec', 'passthru', 'shell_exec'],
        'ssti': ['twig', '{%', '{{'],
    },
    'asp': {
        'sqli': ['mssql', 'sql server', 'exec xp_'],
        'cmdi': ['cmd.exe', 'powershell'],
    },
    'java': {
        'sqli': ['jdbc', 'hibernate', 'prepareStatement'],
        'ssti': ['${', 'freemarker', 'velocity', 'thymeleaf'],
        'ssrf': ['java.net.URL', 'HttpURLConnection'],
    },
    'django': {
        'ssti': ['{{ ', '{% ', 'django.template'],
        'sqli': ['django.db', 'raw('],
    },
    'flask': {
        'ssti': ['{{ ', '{% ', 'jinja2', 'render_template_string'],
    },
    'express': {
        'nosql': ['$gt', '$ne', '$regex', '$where'],
        'ssti': ['#{', '<%='],
    },
    'mysql': {
        'sqli': ['UNION', 'LOAD_FILE', 'INTO OUTFILE', 'information_schema'],
    },
    'postgresql': {
        'sqli': ['pg_sleep', 'string_agg', 'pg_catalog', 'COPY'],
    },
    'mssql': {
        'sqli': ['xp_cmdshell', 'sp_configure', 'WAITFOR', 'master..'],
    },
    'mongodb': {
        'nosql': ['$gt', '$ne', '$regex', '$where', '$exists'],
    },
    'sqlite': {
        'sqli': ['sqlite_master', 'sqlite_version', 'ATTACH'],
    },
}

# WAF-specific evasion profiles
WAF_EVASION_PROFILES = {
    'cloudflare': {
        'delay': 2.0,
        'payload_transforms': ['unicode_encode', 'double_url_encode', 'case_swap'],
        'avoid_patterns': ['<script>', 'UNION SELECT', 'OR 1=1'],
        'recommended_evasion': 'high',
    },
    'modsecurity': {
        'delay': 1.5,
        'payload_transforms': ['comment_inject', 'whitespace_vary', 'case_swap'],
        'avoid_patterns': ['--', '/**/'],
        'recommended_evasion': 'high',
    },
    'akamai': {
        'delay': 2.5,
        'payload_transforms': ['unicode_encode', 'chunk_encode', 'double_url_encode'],
        'avoid_patterns': ['alert(', '<script', 'document.cookie'],
        'recommended_evasion': 'insane',
    },
    'imperva': {
        'delay': 2.0,
        'payload_transforms': ['unicode_encode', 'null_byte', 'double_url_encode'],
        'avoid_patterns': ['SELECT', 'UNION', '<script>'],
        'recommended_evasion': 'insane',
    },
    'sucuri': {
        'delay': 1.5,
        'payload_transforms': ['double_url_encode', 'case_swap'],
        'avoid_patterns': ['UNION', 'SELECT'],
        'recommended_evasion': 'high',
    },
    'aws': {
        'delay': 1.5,
        'payload_transforms': ['unicode_encode', 'whitespace_vary'],
        'avoid_patterns': ['<script>', 'onerror'],
        'recommended_evasion': 'high',
    },
    'f5': {
        'delay': 2.0,
        'payload_transforms': ['comment_inject', 'double_url_encode', 'null_byte'],
        'avoid_patterns': ['UNION', 'OR 1=1', '<script>'],
        'recommended_evasion': 'insane',
    },
    'fortiweb': {
        'delay': 1.5,
        'payload_transforms': ['unicode_encode', 'case_swap'],
        'avoid_patterns': ['alert(', 'SELECT'],
        'recommended_evasion': 'high',
    },
}

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

        # Adaptive feature weights (start from static, learn over time)
        self.learned_weights = {}

        # Confidence calibration tracking
        self.calibration = {
            'predictions': 0,
            'correct': 0,
            'overconfident': 0,
            'underconfident': 0,
        }

        # Real-time state
        self.response_anomalies = []
        self.successful_techniques = []
        self.failed_attempts = defaultdict(int)

        # Discovered vulnerability correlations in this scan
        self.discovered_correlations = []

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
            self.learned_weights = data.get('learned_weights', {})
            self.calibration = data.get('calibration', self.calibration)
            if self.verbose:
                total = sum(sum(v.values()) for v in self.vuln_history.values())
                accuracy = self.get_calibration_accuracy()
                msg = f'AI Engine loaded {total} historical patterns'
                if accuracy is not None:
                    msg += f' (calibration accuracy: {accuracy:.0%})'
                print(f"{Colors.info(msg)}")
        except Exception:
            pass

    def save(self):
        """Persist AI data to disk."""
        data = {
            'vuln_history': {k: dict(v) for k, v in self.vuln_history.items()},
            'payload_effectiveness': {k: dict(v) for k, v in self.payload_effectiveness.items()},
            'learned_weights': self.learned_weights,
            'calibration': self.calibration,
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
        Uses adaptive weights when available from historical learning.
        """
        features = self._extract_features(url, param_name, param_value)
        predictions = {}

        for vuln_type, weight_map in VULN_FEATURE_WEIGHTS.items():
            # Use learned weights if available, fallback to static
            effective_weights = self._get_effective_weights(vuln_type, weight_map)

            score = 0.0
            active_features = 0
            for feature_key, weight in effective_weights.items():
                if features.get(feature_key, False):
                    score += weight
                    active_features += 1

            # Normalize to 0-1 range
            max_possible = sum(effective_weights.values())
            probability = score / max_possible if max_possible > 0 else 0

            # Boost from historical data
            history_boost = self._get_history_boost(vuln_type, param_name)
            probability = min(1.0, probability + history_boost)

            # Apply calibration correction
            probability = self._apply_calibration_correction(probability)

            if probability > 0.1:
                predictions[vuln_type] = round(probability, 3)

        return sorted(predictions.items(), key=lambda x: -x[1])

    def _get_effective_weights(self, vuln_type, static_weights):
        """Return weights blending static defaults with learned adjustments."""
        if vuln_type not in self.learned_weights:
            return static_weights
        learned = self.learned_weights[vuln_type]
        blended = {}
        for key, static_val in static_weights.items():
            learned_val = learned.get(key, static_val)
            # Blend: 70% static + 30% learned to prevent drift
            blended[key] = 0.7 * static_val + 0.3 * learned_val
        return blended

    def _apply_calibration_correction(self, probability):
        """Apply calibration correction based on historical accuracy."""
        total = self.calibration.get('predictions', 0)
        if total < 20:
            return probability  # Not enough data to calibrate

        overconf = self.calibration.get('overconfident', 0)
        underconf = self.calibration.get('underconfident', 0)

        if overconf > underconf * 1.5:
            # Historically overconfident → dampen predictions
            return probability * 0.9
        elif underconf > overconf * 1.5:
            # Historically underconfident → boost predictions
            return min(1.0, probability * 1.1)
        return probability

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

        Combines historical success rates with parameter-specific heuristics
        and tech-stack awareness for targeted payload selection.
        """
        effectiveness = self.payload_effectiveness.get(vuln_type, {})
        tech_hints = self._get_tech_payload_hints(vuln_type)

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

            # Tech-stack bonus: boost payloads matching detected tech
            tech_bonus = 0.0
            if tech_hints:
                payload_lower = payload.lower()
                for hint in tech_hints:
                    if hint.lower() in payload_lower:
                        tech_bonus = 0.15
                        break

            return -(hist_score * 0.45 + length_penalty * 0.15 + param_bonus * 0.2 + tech_bonus * 0.2)

        sorted_payloads = sorted(all_payloads, key=score_payload)
        if max_payloads:
            return sorted_payloads[:max_payloads]
        return sorted_payloads

    def _get_tech_payload_hints(self, vuln_type):
        """Return tech-specific payload hints based on detected tech stack."""
        detected_tech = getattr(self.engine, 'context', None)
        if not detected_tech or not hasattr(detected_tech, 'detected_tech'):
            return []

        hints = []
        for tech in detected_tech.detected_tech:
            tech_lower = tech.lower()
            if tech_lower in TECH_PAYLOAD_HINTS:
                tech_vulns = TECH_PAYLOAD_HINTS[tech_lower]
                if vuln_type in tech_vulns:
                    hints.extend(tech_vulns[vuln_type])
        return hints

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

    def classify_anomaly(self, baseline_time, response_time, baseline_length,
                         response_length, baseline_status, response_status):
        """Classify anomaly into typed categories with individual scores.

        Returns a dict with anomaly type classification and composite score.
        """
        result = {
            'timing': {'score': 0.0, 'deviation': 0.0, 'anomalous': False},
            'content': {'score': 0.0, 'deviation': 0.0, 'anomalous': False},
            'status': {'score': 0.0, 'changed': False, 'anomalous': False},
            'composite_score': 0.0,
            'anomaly_type': 'none',
            'severity': 'none',
        }

        # Timing anomaly
        if baseline_time > 0:
            time_deviation = abs(response_time - baseline_time) / max(baseline_time, MIN_BASELINE_TIME)
            time_score = min(1.0, time_deviation / 3.0)
            result['timing'] = {
                'score': round(time_score, 3),
                'deviation': round(time_deviation, 3),
                'anomalous': time_score > 0.3,
            }

        # Content length anomaly
        if baseline_length > 0:
            length_deviation = abs(response_length - baseline_length) / max(baseline_length, 1)
            length_score = min(1.0, length_deviation / LENGTH_DEVIATION_THRESHOLD)
            result['content'] = {
                'score': round(length_score, 3),
                'deviation': round(length_deviation, 3),
                'anomalous': length_score > 0.3,
            }

        # Status code anomaly
        if baseline_status != response_status:
            status_score = 0.8 if response_status >= 500 else 0.5
            result['status'] = {
                'score': round(status_score, 3),
                'changed': True,
                'anomalous': True,
            }

        # Composite score
        composite = (
            result['timing']['score'] * 0.4
            + result['content']['score'] * 0.3
            + result['status']['score'] * 0.3
        )
        result['composite_score'] = round(composite, 3)

        # Determine primary anomaly type
        anomaly_scores = {
            'timing': result['timing']['score'],
            'content': result['content']['score'],
            'status': result['status']['score'],
        }
        active = {k: v for k, v in anomaly_scores.items() if v > 0.3}

        if len(active) >= 2:
            result['anomaly_type'] = 'combined'
        elif active:
            result['anomaly_type'] = max(active, key=active.get)
        else:
            result['anomaly_type'] = 'none'

        # Severity classification
        if composite >= 0.7:
            result['severity'] = 'high'
        elif composite >= 0.4:
            result['severity'] = 'medium'
        elif composite > 0.1:
            result['severity'] = 'low'

        return result

    # ------------------------------------------------------------------
    # Attack Strategy
    # ------------------------------------------------------------------

    def get_attack_strategy(self, url, parameters):
        """Determine optimal attack strategy for a target.

        Returns a dict with recommended module order, payload limits,
        evasion level, and WAF-specific bypass profile.
        """
        strategy = {
            'module_order': [],
            'payload_limit': None,
            'evasion_recommendation': 'none',
            'aggressive': False,
            'waf_profile': None,
            'tech_payloads': {},
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

        # WAF detection → apply WAF-specific evasion profile
        if hasattr(self.engine, 'adaptive') and self.engine.adaptive.waf_detected:
            waf_name = self.engine.adaptive.waf_name.lower()
            profile = WAF_EVASION_PROFILES.get(waf_name)
            if profile:
                strategy['waf_profile'] = profile
                strategy['evasion_recommendation'] = profile['recommended_evasion']
                strategy['payload_limit'] = 10
            else:
                strategy['evasion_recommendation'] = 'high'
                strategy['payload_limit'] = 15

        # High signal strength → go aggressive
        if hasattr(self.engine, 'adaptive') and self.engine.adaptive.signal_strength > 0.5:
            strategy['aggressive'] = True

        # Add tech-specific payload hints per vuln type
        for vuln_type in strategy['module_order']:
            hints = self._get_tech_payload_hints(vuln_type)
            if hints:
                strategy['tech_payloads'][vuln_type] = hints

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

        # Check for vulnerability correlations
        self._check_correlations(vuln_type)

    def record_failure(self, technique, payload):
        """Record a failed attempt for AI learning."""
        vuln_type = self._technique_to_type(technique)
        self.payload_effectiveness[vuln_type][payload] = max(
            0.0,
            self.payload_effectiveness[vuln_type].get(payload, 0.5) - 0.05,
        )
        self.failed_attempts[vuln_type] += 1

    def record_prediction_outcome(self, predicted_vuln, predicted_prob, was_found):
        """Record whether a prediction was correct for calibration."""
        self.calibration['predictions'] = self.calibration.get('predictions', 0) + 1
        if was_found:
            self.calibration['correct'] = self.calibration.get('correct', 0) + 1
            if predicted_prob < 0.4:
                self.calibration['underconfident'] = self.calibration.get('underconfident', 0) + 1
        else:
            if predicted_prob > 0.6:
                self.calibration['overconfident'] = self.calibration.get('overconfident', 0) + 1

    def update_learned_weights(self, findings):
        """Adjust feature weights based on actual scan findings.

        Called at end of scan. Features that correlated with actual
        findings get boosted; features that didn't are slightly dampened.
        """
        for finding in findings:
            vuln_type = self._technique_to_type(finding.technique)
            if vuln_type not in VULN_FEATURE_WEIGHTS:
                continue

            # Get the param that was vulnerable
            param_name = getattr(finding, 'param', '') or ''
            url = getattr(finding, 'url', '') or ''
            value = getattr(finding, 'value', '') or ''

            features = self._extract_features(url, param_name, value)
            static_weights = VULN_FEATURE_WEIGHTS[vuln_type]

            if vuln_type not in self.learned_weights:
                self.learned_weights[vuln_type] = dict(static_weights)

            for feat_key in static_weights:
                current = self.learned_weights[vuln_type].get(feat_key, static_weights[feat_key])
                if features.get(feat_key, False):
                    # Feature was present and vuln was found → boost
                    self.learned_weights[vuln_type][feat_key] = min(1.0, current + 0.02)
                else:
                    # Feature was absent → slight dampen
                    self.learned_weights[vuln_type][feat_key] = max(0.1, current - 0.005)

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
    # Vulnerability Correlation
    # ------------------------------------------------------------------

    def _check_correlations(self, new_vuln_type):
        """Check if a new finding creates vulnerability correlations."""
        existing_types = set(self.successful_techniques)
        for (vuln_a, vuln_b), correlation in VULN_CORRELATIONS.items():
            if new_vuln_type == vuln_a and vuln_b in existing_types:
                self.discovered_correlations.append(correlation)
            elif new_vuln_type == vuln_b and vuln_a in existing_types:
                self.discovered_correlations.append(correlation)

    def get_vulnerability_correlations(self, findings):
        """Analyze findings for exploitable vulnerability chains.

        Returns a list of correlation dicts with chain label, involved
        findings, and combined severity boost.
        """
        if len(findings) < 2:
            return []

        vuln_types = {}
        for finding in findings:
            vtype = self._technique_to_type(finding.technique)
            vuln_types.setdefault(vtype, []).append(finding)

        chains = []
        seen_chains = set()
        for (vuln_a, vuln_b), correlation in VULN_CORRELATIONS.items():
            if vuln_a in vuln_types and vuln_b in vuln_types:
                chain_key = correlation['chain']
                if chain_key not in seen_chains:
                    seen_chains.add(chain_key)
                    chains.append({
                        'chain': chain_key,
                        'label': correlation['label'],
                        'boost': correlation['boost'],
                        'findings_a': vuln_types[vuln_a],
                        'findings_b': vuln_types[vuln_b],
                    })

        # Sort by severity boost (most impactful chains first)
        chains.sort(key=lambda c: c['boost'], reverse=True)
        return chains

    # ------------------------------------------------------------------
    # Exploit Difficulty Estimation
    # ------------------------------------------------------------------

    def estimate_exploit_difficulty(self, finding):
        """Estimate exploitation difficulty for a finding.

        Returns a dict with difficulty score (0.0=easy, 1.0=hard),
        difficulty label, and contributing factors.
        """
        vuln_type = self._technique_to_type(finding.technique)
        difficulty_info = EXPLOIT_DIFFICULTY.get(vuln_type, {'base': 0.5, 'factors': []})

        base_difficulty = difficulty_info['base']
        active_factors = []

        # WAF increases difficulty
        if hasattr(self.engine, 'adaptive') and hasattr(self.engine.adaptive, 'waf_detected') and self.engine.adaptive.waf_detected:
            if 'waf' in difficulty_info['factors']:
                base_difficulty += 0.2
                active_factors.append('waf_detected')

        # High block rate increases difficulty
        if (hasattr(self.engine, 'adaptive')
                and hasattr(self.engine.adaptive, 'blocked_count')
                and hasattr(self.engine.adaptive, 'total_tested')
                and isinstance(self.engine.adaptive.total_tested, (int, float))):
            block_rate = self.engine.adaptive.blocked_count / max(self.engine.adaptive.total_tested, 1)
            if block_rate > 0.3:
                base_difficulty += 0.15
                active_factors.append('high_block_rate')

        # Low confidence decreases reliability
        conf = getattr(finding, 'confidence', 0.5)
        if conf < 0.5:
            base_difficulty += 0.1
            active_factors.append('low_confidence')

        # Historical success decreases difficulty
        if vuln_type in self.vuln_history and sum(self.vuln_history[vuln_type].values()) > 3:
            base_difficulty -= 0.1
            active_factors.append('historical_success')

        difficulty = max(0.0, min(1.0, base_difficulty))

        if difficulty >= 0.7:
            label = 'hard'
        elif difficulty >= 0.4:
            label = 'medium'
        else:
            label = 'easy'

        return {
            'score': round(difficulty, 2),
            'label': label,
            'factors': active_factors,
            'vuln_type': vuln_type,
        }

    # ------------------------------------------------------------------
    # Confidence Calibration
    # ------------------------------------------------------------------

    def get_calibration_accuracy(self):
        """Return overall prediction accuracy as a ratio, or None if insufficient data."""
        total = self.calibration.get('predictions', 0)
        if total < 5:
            return None
        correct = self.calibration.get('correct', 0)
        return correct / total

    def get_calibration_summary(self):
        """Return detailed calibration statistics."""
        total = self.calibration.get('predictions', 0)
        return {
            'total_predictions': total,
            'correct': self.calibration.get('correct', 0),
            'accuracy': self.get_calibration_accuracy(),
            'overconfident': self.calibration.get('overconfident', 0),
            'underconfident': self.calibration.get('underconfident', 0),
            'calibrated': total >= 20,
        }

    # ------------------------------------------------------------------
    # Post-Exploitation Strategy
    # ------------------------------------------------------------------

    # Maps vulnerability families to ordered exploitation actions
    _EXPLOIT_ACTION_MAP = {
        'sqli': ['extract_db_info', 'extract_tables', 'extract_data'],
        'cmdi': ['enumerate_system', 'upload_shell'],
        'lfi': ['extract_files'],
        'ssrf': ['harvest_metadata'],
        'ssti': ['prove_rce'],
        'upload': ['deploy_shell'],
    }

    _SEVERITY_RANK = {
        'CRITICAL': 5,
        'HIGH': 4,
        'MEDIUM': 3,
        'LOW': 2,
        'INFO': 1,
    }

    def get_exploit_strategy(self, findings: list) -> list:
        """Produce an AI-ranked exploitation plan for confirmed findings.

        Each entry is ``{'finding': <Finding>, 'actions': [str, ...],
        'difficulty': dict, 'correlations': list}``.
        Findings are ranked by a composite score of severity, confidence,
        historical success rate, difficulty, and vulnerability correlations.
        """
        if not findings:
            return []

        # Detect correlations for chain exploitation
        correlations = self.get_vulnerability_correlations(findings)
        correlated_types = set()
        for chain in correlations:
            correlated_types.add(self._technique_to_type(chain['findings_a'][0].technique))
            correlated_types.add(self._technique_to_type(chain['findings_b'][0].technique))

        scored = []
        for finding in findings:
            vuln_type = self._technique_to_type(finding.technique)
            actions = list(self._EXPLOIT_ACTION_MAP.get(vuln_type, []))
            if not actions:
                continue

            sev = self._SEVERITY_RANK.get(finding.severity, 0)
            conf = finding.confidence

            # Historical boost
            history_boost = 0.0
            if vuln_type in self.vuln_history:
                history_boost = min(0.2, sum(
                    self.vuln_history[vuln_type].values()
                ) * 0.05)

            # Correlation boost: findings that form chains are prioritized
            correlation_boost = 0.0
            finding_correlations = []
            if vuln_type in correlated_types:
                for chain in correlations:
                    chain_type_a = self._technique_to_type(chain['findings_a'][0].technique)
                    chain_type_b = self._technique_to_type(chain['findings_b'][0].technique)
                    if vuln_type in (chain_type_a, chain_type_b):
                        correlation_boost = max(correlation_boost, chain['boost'])
                        finding_correlations.append(chain['label'])

            # Difficulty factor: easier exploits are prioritized
            difficulty = self.estimate_exploit_difficulty(finding)
            difficulty_factor = 1.0 - (difficulty['score'] * 0.3)

            score = (sev * conf + history_boost + correlation_boost) * difficulty_factor
            scored.append({
                'finding': finding,
                'actions': actions,
                'difficulty': difficulty,
                'correlations': finding_correlations,
                '_score': score,
            })

        # Sort highest score first
        scored.sort(key=lambda e: e['_score'], reverse=True)

        # Strip internal score key before returning
        for entry in scored:
            entry.pop('_score', None)

        return scored

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
            'calibration': self.get_calibration_summary(),
            'correlations_found': len(self.discovered_correlations),
            'learned_weight_types': len(self.learned_weights),
        }
