#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v9.0 - ULTIMATE EDITION
Scanner Rules Engine

Loads, validates, and exposes the scanner_rules.yaml configuration so
that every pipeline stage (discovery, baseline, scoring, verification,
reporting) can query a single source of truth.

Usage:
    from core.rules_engine import RulesEngine

    rules = RulesEngine()                        # loads default scanner_rules.yaml
    rules = RulesEngine('/path/to/rules.yaml')   # custom path

    rules.runtime     → runtime_defaults section
    rules.baseline    → baseline section
    rules.scoring     → scoring section
    rules.vuln_map    → per-vulnerability configuration
    ...
"""

import json
import os
import copy

import yaml

from config import Colors

# Default rules file lives next to the repo root
_DEFAULT_RULES_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'scanner_rules.yaml',
)

# JSON Schema file for strict validation
_SCHEMA_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'schemas',
    'scanner_rules.schema.json',
)

# Minimal required top-level keys
_REQUIRED_KEYS = {
    'profile', 'pipeline', 'runtime_defaults', 'discovery',
    'baseline', 'scoring', 'verification', 'reporting', 'vuln_map',
}

# Valid scoring component names
_VALID_SCORING_COMPONENTS = {
    'repro', 'context_fit', 'primary_signal', 'secondary_proof',
    'impact', 'instability_penalty', 'ambiguity_penalty',
}


class RulesEngine:
    """Loads, validates, and exposes scanner rules from a YAML file."""

    def __init__(self, rules_path=None, config=None):
        self._path = rules_path or _DEFAULT_RULES_PATH
        self._raw = {}
        self._config = config or {}
        self._load()
        self._apply_config_overrides()

    # ------------------------------------------------------------------
    # Loading & validation
    # ------------------------------------------------------------------

    def _load(self):
        """Load and validate the YAML rules file."""
        if not os.path.isfile(self._path):
            print(f"{Colors.warning(f'Scanner rules not found at {self._path}, using built-in defaults')}")
            self._raw = self._builtin_defaults()
            return

        with open(self._path, 'r', encoding='utf-8') as fh:
            data = yaml.safe_load(fh)

        if not isinstance(data, dict):
            raise ValueError(f'Scanner rules file must contain a YAML mapping, got {type(data).__name__}')

        missing = _REQUIRED_KEYS - set(data.keys())
        if missing:
            print(f"{Colors.warning(f'Scanner rules missing keys: {missing}; falling back to defaults for those sections')}")
            defaults = self._builtin_defaults()
            for key in missing:
                data[key] = defaults[key]

        self._validate_scoring(data.get('scoring', {}))
        self._validate_vuln_map(data.get('vuln_map', {}))
        self._validate_json_schema(data)

        self._raw = data

    def _apply_config_overrides(self):
        """Apply runtime config overrides (CLI flags take precedence)."""
        rt = self._raw.setdefault('runtime_defaults', {})
        if self._config.get('threads'):
            rt['threads'] = self._config['threads']
        if self._config.get('timeout'):
            rt['timeout_seconds'] = self._config['timeout']
        if self._config.get('delay') is not None:
            rt['delay_seconds'] = self._config['delay']

    @staticmethod
    def _validate_scoring(scoring):
        """Validate the scoring section ranges and labels."""
        components = scoring.get('components', {})
        for name, bounds in components.items():
            if name not in _VALID_SCORING_COMPONENTS:
                raise ValueError(f'Unknown scoring component: {name}')
            if not (isinstance(bounds, list) and len(bounds) == 2):
                raise ValueError(f'Scoring component {name} must be [min, max], got {bounds}')
            if bounds[0] > bounds[1]:
                raise ValueError(f'Scoring component {name} min ({bounds[0]}) > max ({bounds[1]})')

        labels = scoring.get('labels', {})
        for label, bounds in labels.items():
            if not (isinstance(bounds, list) and len(bounds) == 2):
                raise ValueError(f'Scoring label {label} must be [min, max], got {bounds}')

    @staticmethod
    def _validate_vuln_map(vuln_map):
        """Validate each vulnerability entry has required keys."""
        required_vuln_keys = {'paths', 'params', 'strong_signals', 'reject_if'}
        for vuln_type, definition in vuln_map.items():
            if not isinstance(definition, dict):
                raise ValueError(f'vuln_map.{vuln_type} must be a mapping')
            missing = required_vuln_keys - set(definition.keys())
            if missing:
                raise ValueError(f'vuln_map.{vuln_type} missing keys: {missing}')

    @staticmethod
    def _validate_json_schema(data):
        """Validate the rules data against the JSON Schema if available.

        Uses ``jsonschema`` when installed; otherwise falls back to a
        soft warning so that the framework still starts.
        """
        if not os.path.isfile(_SCHEMA_PATH):
            return  # schema file not shipped — skip
        try:
            import jsonschema
        except ImportError:
            # jsonschema is optional; skip validation when not installed
            return
        try:
            with open(_SCHEMA_PATH, 'r', encoding='utf-8') as fh:
                schema = json.load(fh)
            jsonschema.validate(instance=data, schema=schema)
        except jsonschema.ValidationError as ve:
            raise ValueError(
                f'Scanner rules schema validation failed: {ve.message} '
                f'(path: {".".join(str(p) for p in ve.absolute_path)})'
            ) from ve

    # ------------------------------------------------------------------
    # Public accessors (read-only deep copies where mutation is a risk)
    # ------------------------------------------------------------------

    @property
    def profile(self):
        return self._raw.get('profile', 'accuracy_only')

    @property
    def pipeline_stages(self):
        return list(self._raw.get('pipeline', {}).get('stages', []))

    @property
    def runtime(self):
        return dict(self._raw.get('runtime_defaults', {}))

    @property
    def discovery(self):
        return dict(self._raw.get('discovery', {}))

    @property
    def baseline(self):
        return dict(self._raw.get('baseline', {}))

    @property
    def prioritization(self):
        return dict(self._raw.get('prioritization', {}))

    @property
    def context_classification(self):
        return dict(self._raw.get('context_classification', {}))

    @property
    def verification(self):
        return dict(self._raw.get('verification', {}))

    @property
    def scoring(self):
        return dict(self._raw.get('scoring', {}))

    @property
    def reporting(self):
        return dict(self._raw.get('reporting', {}))

    @property
    def vuln_map(self):
        return copy.deepcopy(self._raw.get('vuln_map', {}))

    # ------------------------------------------------------------------
    # Convenience helpers used by pipeline stages
    # ------------------------------------------------------------------

    def get_baseline_samples(self):
        """Return (min_samples, max_samples) for baseline measurement."""
        bl = self._raw.get('baseline', {})
        return bl.get('min_samples', 3), bl.get('max_samples', 5)

    def get_noisy_threshold(self):
        """Return the timing stability noisy threshold (stdev/mean ratio)."""
        bl = self._raw.get('baseline', {})
        ts = bl.get('timing_stability', {})
        return ts.get('noisy_threshold', 0.35)

    def get_strip_patterns(self):
        """Return the list of normalization strip pattern names."""
        bl = self._raw.get('baseline', {})
        norm = bl.get('normalization', {})
        return list(norm.get('strip_patterns', []))

    def get_scoring_label(self, score):
        """Map a numeric score (0-100) to a confidence label."""
        labels = self._raw.get('scoring', {}).get('labels', {})
        for label, (lo, hi) in labels.items():
            if lo <= score <= hi:
                return label
        if score >= 85:
            return 'confirmed'
        if score >= 65:
            return 'high'
        if score >= 40:
            return 'likely'
        return 'suspected'

    def get_scoring_component_range(self, component):
        """Return (min, max) for a scoring component."""
        components = self._raw.get('scoring', {}).get('components', {})
        bounds = components.get(component, [0, 0])
        return tuple(bounds)

    def get_verification_config(self):
        """Return the full verification configuration dict."""
        return dict(self._raw.get('verification', {}))

    def get_auto_demote_rules(self):
        """Return the list of auto-demotion rule names."""
        return list(self._raw.get('verification', {}).get('auto_demote_rules', []))

    def get_min_repro_runs(self):
        """Return the minimum reproduction runs for high/confirmed label."""
        return self._raw.get('verification', {}).get(
            'min_repro_runs_for_high_or_confirmed', 3,
        )

    def get_min_strong_signals(self):
        """Return minimum strong signals required."""
        return self._raw.get('verification', {}).get('min_strong_signals', 2)

    def get_vuln_config(self, vuln_type):
        """Return the configuration for a specific vulnerability type.

        Returns an empty dict when the type is not defined in the rules.
        """
        return dict(self._raw.get('vuln_map', {}).get(vuln_type, {}))

    def get_priority_order(self):
        """Return the ordered list of endpoint priority buckets."""
        return list(
            self._raw.get('prioritization', {}).get('order', [])
        )

    def get_keyword_buckets(self):
        """Return the endpoint keyword bucket mapping."""
        return dict(
            self._raw.get('prioritization', {}).get('endpoint_keyword_buckets', {})
        )

    def get_evidence_required(self):
        """Return the list of required evidence fields for reporting."""
        return list(
            self._raw.get('reporting', {}).get('evidence_required', [])
        )

    def get_main_report_labels(self):
        """Return labels that appear in the main report body."""
        return list(
            self._raw.get('reporting', {}).get('main_labels', ['high', 'confirmed'])
        )

    def get_appendix_labels(self):
        """Return labels relegated to the report appendix."""
        return list(
            self._raw.get('reporting', {}).get('appendix_labels', ['suspected', 'likely'])
        )

    def is_noisy_endpoint(self, time_stdev, time_mean):
        """Determine if an endpoint has noisy timing (stdev/mean > threshold)."""
        if time_mean <= 0:
            return False
        ratio = time_stdev / time_mean
        return ratio > self.get_noisy_threshold()

    def should_reject_finding(self, vuln_type, evidence_tags):
        """Check if a finding should be rejected based on vuln_map reject_if rules.

        *evidence_tags* is a set/list of string tags describing the evidence.
        Returns True if any reject_if rule matches.
        """
        vuln_cfg = self.get_vuln_config(vuln_type)
        reject_rules = vuln_cfg.get('reject_if', [])
        if not reject_rules:
            return False
        evidence_set = set(evidence_tags) if not isinstance(evidence_tags, set) else evidence_tags
        return bool(evidence_set & set(reject_rules))

    def matches_vuln_path(self, vuln_type, path):
        """Check if a URL path matches the expected paths for a vuln type."""
        vuln_cfg = self.get_vuln_config(vuln_type)
        vuln_paths = vuln_cfg.get('paths', [])
        if not vuln_paths:
            return True  # no path restriction
        if '*' in vuln_paths:
            return True
        for vp in vuln_paths:
            # Support path templates like /users/{id}
            pattern = vp.split('{')[0]  # match the prefix before any template vars
            if path.startswith(pattern) or pattern in path:
                return True
        return False

    def matches_vuln_param(self, vuln_type, param_name):
        """Check if a parameter name matches the expected params for a vuln type."""
        vuln_cfg = self.get_vuln_config(vuln_type)
        vuln_params = vuln_cfg.get('params', [])
        if not vuln_params:
            return True  # no param restriction
        return param_name.lower() in [p.lower() for p in vuln_params]

    # ------------------------------------------------------------------
    # Built-in fallback defaults (mirrors scanner_rules.yaml structure)
    # ------------------------------------------------------------------

    @staticmethod
    def _builtin_defaults():
        """Return sensible built-in defaults when no YAML file is found."""
        return {
            'profile': 'accuracy_only',
            'pipeline': {
                'stages': [
                    'discovery', 'baseline', 'context_classification',
                    'prioritized_testing', 'verification', 'scoring', 'reporting',
                ],
            },
            'runtime_defaults': {
                'threads': 10,
                'timeout_seconds': 15,
                'retries': 2,
                'delay_seconds': 0.25,
                'jitter': True,
                'backoff': 'exponential',
            },
            'discovery': {
                'waf_bypass': True,
                'reconscan': True,
                'sources': ['links', 'forms', 'js_references', 'api_patterns', 'graphql_endpoints'],
                'collect_inputs': [
                    'query_params', 'path_params', 'form_fields', 'json_keys',
                    'headers', 'cookies', 'jwt_claims', 'multipart_fields',
                ],
            },
            'baseline': {
                'min_samples': 3,
                'max_samples': 5,
                'required_metrics': [
                    'status_code', 'normalized_body_hash', 'body_length',
                    'timing_mean', 'timing_stdev', 'timing_p95',
                ],
                'normalization': {
                    'strip_patterns': [
                        'timestamps', 'request_ids', 'csrf_tokens',
                        'nonces', 'rotating_tokens', 'random_fragments',
                    ],
                },
                'timing_stability': {
                    'formula': 'stdev/mean',
                    'noisy_threshold': 0.35,
                },
            },
            'prioritization': {
                'order': [
                    'auth_admin_account', 'object_reference_apis',
                    'upload_import_export', 'fetch_webhook_pdf_image_proxy',
                    'search_filter_sort_report', 'remaining',
                ],
                'endpoint_keyword_buckets': {
                    'auth_admin_account': ['login', 'register', 'reset', 'profile', 'admin', 'account'],
                    'upload_import_export': ['upload', 'import', 'export', 'download', 'attachment', 'avatar'],
                    'fetch_webhook_pdf_image_proxy': ['fetch', 'preview', 'webhook', 'pdf', 'image-proxy', 'proxy'],
                    'search_filter_sort_report': ['search', 'filter', 'sort', 'report', 'list'],
                },
            },
            'context_classification': {
                'sinks': [
                    'sql_like', 'html_js_attribute_reflection', 'server_side_url_fetch',
                    'object_authorization_reference', 'template_render', 'xml_parser',
                    'file_processor', 'command_like_processor', 'redirect_target',
                    'cors_policy', 'graphql_authz',
                ],
            },
            'verification': {
                'min_repro_runs_for_high_or_confirmed': 3,
                'min_strong_signals': 2,
                'confirmed_requires_secondary_proof': True,
                'auto_demote_rules': [
                    'reflection_only', 'single_timing_spike', 'generic_500_only',
                    'missing_secondary_proof', 'unstable_baseline_timing_only',
                ],
                'noisy_timing_cap': {
                    'enabled': True,
                    'max_label_if_timing_only_on_noisy_endpoint': 'likely',
                },
            },
            'scoring': {
                'formula': 'repro + context_fit + primary_signal + secondary_proof + impact - instability_penalty - ambiguity_penalty',
                'components': {
                    'repro': [0, 30],
                    'context_fit': [0, 20],
                    'primary_signal': [0, 20],
                    'secondary_proof': [0, 20],
                    'impact': [0, 10],
                    'instability_penalty': [0, 20],
                    'ambiguity_penalty': [0, 10],
                },
                'labels': {
                    'suspected': [0, 39],
                    'likely': [40, 64],
                    'high': [65, 84],
                    'confirmed': [85, 100],
                },
            },
            'reporting': {
                'main_labels': ['high', 'confirmed'],
                'appendix_labels': ['suspected', 'likely'],
                'require_why_not_confirmed': True,
                'evidence_required': [
                    'endpoint', 'method', 'parameter', 'context',
                    'baseline_stats', 'observed_deltas', 'confirmation_runs',
                    'secondary_proof_artifact', 'confidence_score',
                    'confidence_reasons', 'downgrade_reason',
                ],
            },
            'vuln_map': {},
        }

    def to_dict(self):
        """Return a deep copy of the entire rules configuration."""
        return copy.deepcopy(self._raw)
