#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — Phase L: Out-of-Band (OOB) Callback Infrastructure

Provides a lightweight HTTP callback server and DNS polling integration
for confirming blind vulnerabilities (SSRF, XXE, SQLi, CMDi, Blind XSS).
"""

import uuid
import time
import threading
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs


class _OOBHandler(BaseHTTPRequestHandler):
    """HTTP handler that records incoming callbacks."""

    server: 'OOBCallbackServer'  # type hint for IDE

    def do_GET(self):
        self._record_hit()
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'OK')

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length else b''
        self._record_hit(body=body.decode(errors='replace'))
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'OK')

    def _record_hit(self, body=''):
        """Extract the token from the path and record the callback."""
        # Expected path: /callback/<token>  or  /<token>
        parts = self.path.strip('/').split('/')
        token = parts[-1] if parts else ''
        self.server.record_callback(
            token=token,
            source_ip=self.client_address[0],
            path=self.path,
            method=self.command,
            headers=dict(self.headers),
            body=body,
        )

    def log_message(self, format, *args):
        """Silence default stderr logging."""
        pass


class OOBCallbackServer:
    """Lightweight HTTP callback server for blind detection."""

    def __init__(self, listen_host='0.0.0.0', listen_port=8888,
                 external_domain=None):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.external_domain = external_domain or f'localhost:{listen_port}'
        self._callbacks: dict = {}  # token → list of hit records
        self._lock = threading.Lock()
        self._server = None
        self._thread = None
        self._running = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self):
        """Start the callback server in a background daemon thread."""
        if self._running:
            return
        try:
            self._server = HTTPServer(
                (self.listen_host, self.listen_port), _OOBHandler)
            self._server.record_callback = self._record
            self._running = True
            self._thread = threading.Thread(target=self._server.serve_forever,
                                            daemon=True)
            self._thread.start()
        except OSError:
            # Port already in use — skip
            self._running = False

    def stop(self):
        """Shut down the callback server."""
        if self._server:
            self._server.shutdown()
            self._running = False

    # ------------------------------------------------------------------
    # Token management
    # ------------------------------------------------------------------

    def generate_token(self, vuln_type='', url='', param=''):
        """Create a unique token and return it + callback URL."""
        token = uuid.uuid4().hex[:16]
        with self._lock:
            self._callbacks[token] = {
                'hits': [],
                'meta': {'vuln_type': vuln_type, 'url': url, 'param': param},
                'created': time.time(),
            }
        callback_url = f'http://{self.external_domain}/callback/{token}'
        return token, callback_url

    def get_dns_subdomain(self, token):
        """Return a unique DNS subdomain for DNS callback correlation."""
        return f'{token}.oob.{self.external_domain}'

    def check_token(self, token, timeout=10):
        """Wait up to *timeout* seconds for a callback hit on *token*."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                entry = self._callbacks.get(token)
                if entry and entry['hits']:
                    return entry['hits']
            time.sleep(0.5)
        return []

    def get_all_hits(self):
        """Return all recorded callbacks."""
        with self._lock:
            return dict(self._callbacks)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _record(self, token, **kwargs):
        """Thread-safe callback recording."""
        with self._lock:
            if token not in self._callbacks:
                self._callbacks[token] = {
                    'hits': [], 'meta': {}, 'created': time.time()}
            self._callbacks[token]['hits'].append({
                'time': time.time(), **kwargs})


class InteractShPoller:
    """Poll interact.sh (ProjectDiscovery OOB service) for DNS hits.

    Usage:
        poller = InteractShPoller()
        subdomain = poller.get_subdomain()  # unique per scan
        # ... inject subdomain into payloads ...
        hits = poller.poll()
    """

    INTERACT_SH_URL = 'https://oast.live'  # public interact.sh endpoint

    def __init__(self, server_url=None):
        self.server_url = server_url or self.INTERACT_SH_URL
        self.correlation_id = uuid.uuid4().hex[:12]
        self._subdomain = f'{self.correlation_id}.oast.live'

    def get_subdomain(self):
        """Return the subdomain to embed in payloads."""
        return self._subdomain

    def poll(self):
        """Poll for interactions. Returns a list of hit dicts or []."""
        try:
            import requests
            resp = requests.get(
                f'{self.server_url}/poll?id={self.correlation_id}',
                timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                return data.get('data', [])
        except Exception:
            pass
        return []


class OOBManager:
    """High-level OOB manager wired into the scan engine.

    Provides helpers that modules can call to get callback URLs and
    later confirm blind findings.
    """

    def __init__(self, engine):
        self.engine = engine
        config = engine.config
        self.enabled = config.get('oob_enabled', False)
        self.http_server = None
        self.interact_poller = None

        if self.enabled:
            port = config.get('oob_port', 8888)
            domain = config.get('oob_domain', None)
            self.http_server = OOBCallbackServer(
                listen_port=port, external_domain=domain)
            self.http_server.start()

            if config.get('oob_interact_sh', False):
                self.interact_poller = InteractShPoller(
                    config.get('oob_interact_url'))

    def get_callback_url(self, vuln_type='', url='', param=''):
        """Return (token, callback_url) or (None, None) when disabled."""
        if not self.http_server:
            return None, None
        return self.http_server.generate_token(vuln_type, url, param)

    def get_dns_canary(self, token):
        """Return a unique DNS subdomain for the given token."""
        if self.interact_poller:
            return f'{token}.{self.interact_poller.get_subdomain()}'
        if self.http_server:
            return self.http_server.get_dns_subdomain(token)
        return None

    def check(self, token, timeout=10):
        """Check if a callback was received for *token*."""
        if self.http_server:
            hits = self.http_server.check_token(token, timeout=timeout)
            if hits:
                return hits
        if self.interact_poller:
            return self.interact_poller.poll()
        return []

    def stop(self):
        """Stop the OOB server."""
        if self.http_server:
            self.http_server.stop()
