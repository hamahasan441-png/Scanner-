#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ATOMIC FRAMEWORK v8.0 - ULTIMATE EDITION
Intercepting Proxy - HTTP/HTTPS Traffic Intercept & Modify"""

import json
import re
import time
import uuid
import threading
import socketserver
import http.server
import urllib.request
import urllib.error
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional, List, Dict
from urllib.parse import urlparse


# Maximum proxy history entries before oldest are discarded
MAX_HISTORY_SIZE = 10000

# Default timeout for upstream requests (seconds)
UPSTREAM_TIMEOUT = 30


@dataclass
class ProxyRequest:
    """Captured HTTP request."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    method: str = ''
    url: str = ''
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ''
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    client_address: str = ''


@dataclass
class ProxyResponse:
    """Captured HTTP response."""
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ''
    elapsed: float = 0.0


@dataclass
class ProxyHistoryEntry:
    """Single request/response pair in the proxy history."""
    request: ProxyRequest = field(default_factory=ProxyRequest)
    response: Optional[ProxyResponse] = None
    intercepted: bool = False
    modified: bool = False
    notes: str = ''


class _PendingIntercept:
    """Internal wrapper for a request waiting on intercept decision."""

    def __init__(self, proxy_request: ProxyRequest):
        self.proxy_request = proxy_request
        self.event = threading.Event()
        self.action: Optional[str] = None          # 'forward' or 'drop'
        self.modified_request: Optional[dict] = None


class _ProxyHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler that forwards requests upstream.

    Attributes are injected via the server instance which holds a
    reference back to the owning ``InterceptProxy``.
    """

    # Suppress default stderr logging
    def log_message(self, format, *args):
        pass

    def _get_proxy(self) -> 'InterceptProxy':
        return self.server.proxy  # type: ignore[attr-defined]

    # --- HTTP verb handlers ---------------------------------------------------

    def do_GET(self):
        self._handle_request('GET')

    def do_POST(self):
        self._handle_request('POST')

    def do_PUT(self):
        self._handle_request('PUT')

    def do_DELETE(self):
        self._handle_request('DELETE')

    def do_PATCH(self):
        self._handle_request('PATCH')

    def do_HEAD(self):
        self._handle_request('HEAD')

    def do_OPTIONS(self):
        self._handle_request('OPTIONS')

    # --- Core forwarding logic ------------------------------------------------

    def _read_body(self) -> str:
        length = int(self.headers.get('Content-Length', 0))
        if length > 0:
            return self.rfile.read(length).decode('utf-8', errors='replace')
        return ''

    def _collect_headers(self) -> Dict[str, str]:
        result: Dict[str, str] = {}
        for key in self.headers:
            result[key] = self.headers[key]
        return result

    def _handle_request(self, method: str):
        proxy = self._get_proxy()

        body = self._read_body()
        headers = self._collect_headers()
        client = f'{self.client_address[0]}:{self.client_address[1]}'

        proxy_req = ProxyRequest(
            id=str(uuid.uuid4()),
            method=method,
            url=self.path,
            headers=headers,
            body=body,
            timestamp=datetime.now(timezone.utc).isoformat(),
            client_address=client,
        )

        # Apply request rules
        was_modified = proxy._apply_request_rules(proxy_req)

        intercepted = False
        # Intercept gate
        if proxy._intercept_enabled:
            intercepted = True
            pending = _PendingIntercept(proxy_req)
            with proxy._pending_lock:
                proxy._pending_requests[proxy_req.id] = pending

            # Block until analyst decides
            pending.event.wait()

            if pending.action == 'drop':
                entry = ProxyHistoryEntry(
                    request=proxy_req,
                    response=None,
                    intercepted=True,
                    modified=was_modified,
                    notes='Dropped by analyst',
                )
                proxy._add_history(entry)
                self.send_error(444, 'Request dropped')
                return

            if pending.modified_request is not None:
                was_modified = True
                mod = pending.modified_request
                proxy_req.method = mod.get('method', proxy_req.method)
                proxy_req.url = mod.get('url', proxy_req.url)
                proxy_req.headers = mod.get('headers', proxy_req.headers)
                proxy_req.body = mod.get('body', proxy_req.body)

        # Forward upstream
        start = time.monotonic()
        try:
            resp = proxy._forward_upstream(proxy_req)
        except Exception as exc:
            entry = ProxyHistoryEntry(
                request=proxy_req,
                response=ProxyResponse(status_code=502, body=str(exc)),
                intercepted=intercepted,
                modified=was_modified,
                notes=f'Upstream error: {exc}',
            )
            proxy._add_history(entry)
            self.send_error(502, f'Bad Gateway: {exc}')
            return
        elapsed = time.monotonic() - start

        proxy_resp = ProxyResponse(
            status_code=resp['status'],
            headers=resp['headers'],
            body=resp['body'],
            elapsed=round(elapsed, 4),
        )

        # Apply response rules
        resp_modified = proxy._apply_response_rules(proxy_resp)

        entry = ProxyHistoryEntry(
            request=proxy_req,
            response=proxy_resp,
            intercepted=intercepted,
            modified=was_modified or resp_modified,
        )
        proxy._add_history(entry)

        # Send response back to client
        self.send_response(proxy_resp.status_code)
        for key, val in proxy_resp.headers.items():
            if key.lower() not in ('transfer-encoding', 'content-encoding', 'content-length'):
                self.send_header(key, val)
        resp_body = proxy_resp.body.encode('utf-8', errors='replace')
        self.send_header('Content-Length', str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)


class _ReusableTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class InterceptProxy:
    """HTTP/HTTPS intercepting proxy with history and rules engine.

    Usage::

        proxy = InterceptProxy(port=8080, intercept=True)
        proxy.start()
        # ... inspect / modify traffic ...
        proxy.stop()
    """

    def __init__(self, host: str = '127.0.0.1', port: int = 8080,
                 intercept: bool = False):
        self.host = host
        self.port = port

        # Intercept state
        self._intercept_enabled = intercept
        self._pending_lock = threading.Lock()
        self._pending_requests: Dict[str, _PendingIntercept] = {}

        # History
        self._history_lock = threading.Lock()
        self._history: List[ProxyHistoryEntry] = []

        # Rules
        self._request_rules: List[Dict] = []
        self._response_rules: List[Dict] = []

        # Server state
        self._server: Optional[_ReusableTCPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    # --- Lifecycle ------------------------------------------------------------

    def start(self):
        """Start the proxy server in a background thread."""
        if self._running:
            return
        server = _ReusableTCPServer((self.host, self.port), _ProxyHandler)
        server.proxy = self  # type: ignore[attr-defined]
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, daemon=True)
        self._thread.start()
        self._running = True

    def stop(self):
        """Shut down the proxy server gracefully."""
        if not self._running:
            return
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._server = None
        self._thread = None
        self._running = False
        # Release any blocked intercepts
        with self._pending_lock:
            for pending in self._pending_requests.values():
                pending.action = 'forward'
                pending.event.set()
            self._pending_requests.clear()

    @property
    def is_running(self) -> bool:
        """Whether the proxy server is currently running."""
        return self._running

    # --- Intercept controls ---------------------------------------------------

    def set_intercept(self, enabled: bool):
        """Enable or disable request interception."""
        self._intercept_enabled = bool(enabled)
        if not self._intercept_enabled:
            # Auto-forward all pending requests
            with self._pending_lock:
                for pending in self._pending_requests.values():
                    pending.action = 'forward'
                    pending.event.set()
                self._pending_requests.clear()

    def get_pending_request(self) -> Optional[ProxyRequest]:
        """Return the next intercepted request awaiting action, or None."""
        with self._pending_lock:
            for pending in self._pending_requests.values():
                if not pending.event.is_set():
                    return pending.proxy_request
        return None

    def forward_request(self, request_id: str,
                        modified_request: Optional[dict] = None):
        """Forward an intercepted request, optionally with modifications.

        Parameters
        ----------
        request_id : str
            The ``ProxyRequest.id`` of the intercepted request.
        modified_request : dict, optional
            Dict with any of 'method', 'url', 'headers', 'body' to override.
        """
        with self._pending_lock:
            pending = self._pending_requests.pop(request_id, None)
        if pending is None:
            raise KeyError(f'No pending request with id {request_id}')
        pending.action = 'forward'
        pending.modified_request = modified_request
        pending.event.set()

    def drop_request(self, request_id: str):
        """Drop an intercepted request so it is never forwarded."""
        with self._pending_lock:
            pending = self._pending_requests.pop(request_id, None)
        if pending is None:
            raise KeyError(f'No pending request with id {request_id}')
        pending.action = 'drop'
        pending.event.set()

    # --- History --------------------------------------------------------------

    def _add_history(self, entry: ProxyHistoryEntry):
        with self._history_lock:
            if len(self._history) >= MAX_HISTORY_SIZE:
                self._history = self._history[-(MAX_HISTORY_SIZE // 2):]
            self._history.append(entry)

    def get_history(self) -> List[ProxyHistoryEntry]:
        """Return a copy of the full proxy history."""
        with self._history_lock:
            return list(self._history)

    def clear_history(self):
        """Remove all entries from proxy history."""
        with self._history_lock:
            self._history.clear()

    def filter_history(self, url_pattern: Optional[str] = None,
                       method: Optional[str] = None,
                       status_code: Optional[int] = None) -> List[ProxyHistoryEntry]:
        """Filter proxy history by URL regex, HTTP method, or status code."""
        with self._history_lock:
            results = list(self._history)

        if url_pattern is not None:
            regex = re.compile(url_pattern, re.IGNORECASE)
            results = [e for e in results if regex.search(e.request.url)]
        if method is not None:
            upper = method.upper()
            results = [e for e in results if e.request.method == upper]
        if status_code is not None:
            results = [
                e for e in results
                if e.response is not None and e.response.status_code == status_code
            ]
        return results

    def export_history(self, format: str = 'json') -> str:
        """Export proxy history as a JSON string."""
        history = self.get_history()
        data = []
        for entry in history:
            item: Dict = {
                'request': {
                    'id': entry.request.id,
                    'method': entry.request.method,
                    'url': entry.request.url,
                    'headers': entry.request.headers,
                    'body': entry.request.body,
                    'timestamp': entry.request.timestamp,
                    'client_address': entry.request.client_address,
                },
                'intercepted': entry.intercepted,
                'modified': entry.modified,
                'notes': entry.notes,
            }
            if entry.response is not None:
                item['response'] = {
                    'status_code': entry.response.status_code,
                    'headers': entry.response.headers,
                    'body': entry.response.body,
                    'elapsed': entry.response.elapsed,
                }
            else:
                item['response'] = None
            data.append(item)
        return json.dumps(data, indent=2)

    # --- Rules engine ---------------------------------------------------------

    def add_request_rule(self, rule: dict):
        """Add an auto-modification rule for outgoing requests.

        Parameters
        ----------
        rule : dict
            Must contain 'match' (regex), 'replace' (str), and 'scope'
            which is one of 'url', 'header', 'body'.
        """
        if not all(k in rule for k in ('match', 'replace', 'scope')):
            raise ValueError("Rule must contain 'match', 'replace', and 'scope'")
        if rule['scope'] not in ('url', 'header', 'body'):
            raise ValueError("Rule scope must be 'url', 'header', or 'body'")
        self._request_rules.append(dict(rule))

    def add_response_rule(self, rule: dict):
        """Add an auto-modification rule for incoming responses.

        Parameters
        ----------
        rule : dict
            Must contain 'match' (regex), 'replace' (str), and 'scope'
            which is one of 'header', 'body', 'status'.
        """
        if not all(k in rule for k in ('match', 'replace', 'scope')):
            raise ValueError("Rule must contain 'match', 'replace', and 'scope'")
        if rule['scope'] not in ('header', 'body', 'status'):
            raise ValueError("Rule scope must be 'header', 'body', or 'status'")
        self._response_rules.append(dict(rule))

    def clear_rules(self):
        """Remove all request and response modification rules."""
        self._request_rules.clear()
        self._response_rules.clear()

    # --- Internal helpers -----------------------------------------------------

    def _apply_request_rules(self, req: ProxyRequest) -> bool:
        """Apply auto-modification rules to *req*. Returns True if modified."""
        modified = False
        for rule in self._request_rules:
            pattern = rule['match']
            replacement = rule['replace']
            scope = rule['scope']
            if scope == 'url':
                new_url = re.sub(pattern, replacement, req.url)
                if new_url != req.url:
                    req.url = new_url
                    modified = True
            elif scope == 'header':
                for key in list(req.headers):
                    new_val = re.sub(pattern, replacement, req.headers[key])
                    if new_val != req.headers[key]:
                        req.headers[key] = new_val
                        modified = True
            elif scope == 'body':
                new_body = re.sub(pattern, replacement, req.body)
                if new_body != req.body:
                    req.body = new_body
                    modified = True
        return modified

    def _apply_response_rules(self, resp: ProxyResponse) -> bool:
        """Apply auto-modification rules to *resp*. Returns True if modified."""
        modified = False
        for rule in self._response_rules:
            pattern = rule['match']
            replacement = rule['replace']
            scope = rule['scope']
            if scope == 'body':
                new_body = re.sub(pattern, replacement, resp.body)
                if new_body != resp.body:
                    resp.body = new_body
                    modified = True
            elif scope == 'header':
                for key in list(resp.headers):
                    new_val = re.sub(pattern, replacement, resp.headers[key])
                    if new_val != resp.headers[key]:
                        resp.headers[key] = new_val
                        modified = True
            elif scope == 'status':
                try:
                    new_code = int(replacement)
                    if new_code != resp.status_code:
                        resp.status_code = new_code
                        modified = True
                except (ValueError, TypeError):
                    pass
        return modified

    def _forward_upstream(self, req: ProxyRequest) -> dict:
        """Send the request upstream and return a response dict."""
        url = req.url
        headers = {k: v for k, v in req.headers.items()
                   if k.lower() not in ('host', 'proxy-connection')}
        body_bytes = req.body.encode('utf-8') if req.body else None

        # Reject XML bodies that contain external entity declarations (XXE)
        if body_bytes:
            content_type = (headers.get('Content-Type', '') or '').lower()
            if 'xml' in content_type or (req.body and req.body.lstrip().startswith('<?xml')):
                body_upper = req.body.upper()
                if '<!ENTITY' in body_upper or '<!DOCTYPE' in body_upper:
                    return {
                        'status': 400,
                        'headers': {},
                        'body': 'Request blocked: potentially dangerous XML entity declaration',
                    }

        request = urllib.request.Request(
            url, data=body_bytes, headers=headers, method=req.method,
        )
        try:
            with urllib.request.urlopen(request, timeout=UPSTREAM_TIMEOUT) as resp:
                resp_body = resp.read().decode('utf-8', errors='replace')
                resp_headers = {k: v for k, v in resp.getheaders()}
                return {
                    'status': resp.status,
                    'headers': resp_headers,
                    'body': resp_body,
                }
        except urllib.error.HTTPError as exc:
            resp_body = exc.read().decode('utf-8', errors='replace') if exc.fp else ''
            resp_headers = dict(exc.headers) if exc.headers else {}
            return {
                'status': exc.code,
                'headers': resp_headers,
                'body': resp_body,
            }
