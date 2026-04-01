#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v8.0 - ULTIMATE EDITION
Brute Force Module

Form-based and HTTP-auth credential brute-forcing.  Detects login
forms via common field names, applies a configurable wordlist, and
stops on confirmed success or detected lockout.
"""

import itertools
from typing import List, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse

from config import Colors


# ── Default mini-wordlist (used when no external file is given) ───────────
DEFAULT_USERNAMES = [
    'admin', 'administrator', 'root', 'user', 'test', 'guest',
    'info', 'adm', 'mysql', 'postgres', 'ftp', 'operator',
]

DEFAULT_PASSWORDS = [
    'admin', 'password', '123456', '12345678', 'root', 'toor',
    'pass', 'test', 'guest', 'master', 'changeme', 'letmein',
    'qwerty', 'abc123', 'monkey', 'dragon', 'login', '1234',
    'password1', 'admin123', 'welcome', 'shadow', 'sunshine',
]

# Field names commonly used for login forms
USERNAME_FIELDS = {
    'username', 'user', 'login', 'email', 'user_name', 'userid',
    'user_id', 'name', 'uname', 'usr', 'account',
}
PASSWORD_FIELDS = {
    'password', 'pass', 'passwd', 'pwd', 'secret', 'user_password',
    'user_pass', 'passw', 'passwort',
}

# Indicators of a failed login (looked for in response body)
FAILURE_INDICATORS = [
    'invalid', 'incorrect', 'wrong', 'failed', 'error', 'denied',
    'bad credentials', 'authentication failed', 'login failed',
    'try again', 'not found', 'unauthorized',
]

# Indicators of successful login
SUCCESS_INDICATORS = [
    'dashboard', 'welcome', 'logout', 'sign out', 'my account',
    'profile', 'settings', 'admin panel',
]

# Lockout detection
LOCKOUT_INDICATORS = [
    'locked', 'too many', 'rate limit', 'blocked', 'captcha',
    'try again later', 'temporarily', 'suspended',
]

MAX_ATTEMPTS = 500  # safety cap
SUCCESS_LENGTH_CHANGE_THRESHOLD = 0.4  # min body-length ratio change to signal success


class BruteForceModule:
    """Form-based credential brute-forcing."""

    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.config = engine.config
        self.verbose = self.config.get('verbose', False)
        self.results: List[Dict] = []

    # ─── public API ──────────────────────────────────────────────────

    def run(
        self,
        forms: List[Dict],
        usernames: Optional[List[str]] = None,
        passwords: Optional[List[str]] = None,
    ) -> List[Dict]:
        """Brute-force login forms discovered during crawling.

        Parameters
        ----------
        forms : list[dict]
            Forms extracted by the crawler.  Each dict should have
            ``url``, ``action``, ``method``, and ``inputs``.
        usernames / passwords : list[str] | None
            Custom wordlists.  Falls back to built-in defaults.

        Returns
        -------
        list[dict]
            Successfully cracked credentials (``url``, ``username``,
            ``password``).
        """
        usernames = usernames or DEFAULT_USERNAMES
        passwords = passwords or DEFAULT_PASSWORDS

        login_forms = self._identify_login_forms(forms)
        if not login_forms:
            if self.verbose:
                print(f"{Colors.info('No login forms identified for brute-force')}")
            return self.results

        print(f"\n{Colors.BOLD}{'─' * 60}{Colors.RESET}")
        print(f"{Colors.CYAN}  Brute Force ({len(login_forms)} login forms){Colors.RESET}")
        print(f"{Colors.BOLD}{'─' * 60}{Colors.RESET}\n")

        for form in login_forms:
            self._brute_form(form, usernames, passwords)

        if self.results:
            print(f"\n{Colors.success(f'Brute force: {len(self.results)} credentials found!')}")
        else:
            print(f"\n{Colors.info('Brute force: no credentials found')}")

        return self.results

    # ─── internals ───────────────────────────────────────────────────

    def _identify_login_forms(self, forms: List[Dict]) -> List[Dict]:
        """Return forms that look like login forms."""
        login_forms = []
        for form in forms:
            inputs = form.get('inputs', [])
            input_names = {
                inp.get('name', '').lower()
                for inp in inputs
                if inp.get('name')
            }
            has_user = bool(input_names & USERNAME_FIELDS)
            has_pass = bool(input_names & PASSWORD_FIELDS)
            if has_pass:  # password field is the minimum requirement
                login_forms.append({
                    'url': form.get('url', ''),
                    'action': form.get('action', ''),
                    'method': form.get('method', 'POST').upper(),
                    'inputs': inputs,
                    'user_field': (input_names & USERNAME_FIELDS) or None,
                    'pass_field': (input_names & PASSWORD_FIELDS) or None,
                    'has_user': has_user,
                })
        return login_forms

    def _brute_form(
        self,
        form: Dict,
        usernames: List[str],
        passwords: List[str],
    ) -> None:
        """Execute brute-force against a single login form."""
        action = form['action'] or form['url']
        if action and not action.startswith('http'):
            action = urljoin(form['url'], action)

        method = form['method']

        # Resolve field names
        user_field = next(iter(form['user_field'])) if form['user_field'] else None
        pass_field = next(iter(form['pass_field'])) if form['pass_field'] else None

        if not pass_field:
            return

        # Collect static hidden fields
        static_fields: Dict[str, str] = {}
        for inp in form['inputs']:
            name = inp.get('name', '')
            if name.lower() not in USERNAME_FIELDS and name.lower() not in PASSWORD_FIELDS:
                static_fields[name] = inp.get('value', '')

        # Get baseline failure response
        baseline_resp = self._send_attempt(
            action, method, user_field, 'aaaa_invalid_user',
            pass_field, 'aaaa_invalid_pass', static_fields,
        )
        baseline_text = baseline_resp.text.lower() if baseline_resp else ''
        baseline_len = len(baseline_text)

        attempts = 0
        combo_iter = (
            itertools.product(usernames, passwords)
            if user_field
            else ((None, p) for p in passwords)
        )

        for username, password in combo_iter:
            if attempts >= MAX_ATTEMPTS:
                print(f"{Colors.warning('  Max attempts reached, stopping')}")
                break
            attempts += 1

            resp = self._send_attempt(
                action, method, user_field, username,
                pass_field, password, static_fields,
            )
            if not resp:
                continue

            resp_lower = resp.text.lower()

            # Lockout detection
            if any(ind in resp_lower for ind in LOCKOUT_INDICATORS):
                print(f"{Colors.warning('  Account lockout detected — aborting')}")
                break

            # Success heuristics
            if self._is_success(resp, resp_lower, baseline_text, baseline_len):
                cred = {
                    'url': action,
                    'username': username or '(none)',
                    'password': password,
                }
                self.results.append(cred)
                print(
                    f"  {Colors.GREEN}[FOUND]{Colors.RESET} "
                    f"{cred['username']}:{cred['password']}  →  {action}"
                )
                # Add as finding to the engine
                self._add_finding(action, username, password)
                break  # move to next form

            if self.verbose and attempts % 50 == 0:
                print(f"  {Colors.info(f'  {attempts} attempts tried...')}")

    def _send_attempt(
        self, url, method, user_field, username,
        pass_field, password, static_fields,
    ):
        """Send a single login attempt."""
        data = dict(static_fields)
        if user_field and username:
            data[user_field] = username
        data[pass_field] = password

        try:
            return self.requester.request(
                url, method, data=data, allow_redirects=True,
            )
        except Exception:
            return None

    @staticmethod
    def _is_success(resp, resp_lower: str, baseline_text: str, baseline_len: int) -> bool:
        """Heuristic: decide whether a response represents successful auth."""
        # 302 redirect to a different page is a strong signal
        if resp.status_code in (301, 302, 303) and resp.headers.get('Location'):
            loc = resp.headers['Location'].lower()
            if any(kw in loc for kw in ('dashboard', 'home', 'account', 'profile', 'admin')):
                return True

        # Positive keywords present AND negative keywords absent
        has_success = any(kw in resp_lower for kw in SUCCESS_INDICATORS)
        has_failure = any(kw in resp_lower for kw in FAILURE_INDICATORS)
        if has_success and not has_failure:
            return True

        # Significant body-length change from baseline failure
        if baseline_len > 0:
            ratio = abs(len(resp_lower) - baseline_len) / baseline_len
            if ratio > SUCCESS_LENGTH_CHANGE_THRESHOLD and not has_failure:
                return True

        return False

    def _add_finding(self, url: str, username: Optional[str], password: str):
        """Register a brute-force finding with the engine."""
        from core.engine import Finding
        finding = Finding(
            technique='Brute Force - Weak Credentials',
            url=url,
            method='POST',
            param=f'username={username or "(none)"}',
            payload=f'password={password}',
            evidence=f'Valid credentials found: {username or "(none)"}:{password}',
            severity='HIGH',
            confidence=0.9,
        )
        self.engine.add_finding(finding)
