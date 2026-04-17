#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the intercepting proxy (core/proxy.py)."""

import json
import threading
import unittest
from unittest.mock import patch, MagicMock

from core.proxy import (
    InterceptProxy,
    ProxyRequest,
    ProxyResponse,
    ProxyHistoryEntry,
    _PendingIntercept,
    _ProxyHandler,
    MAX_HISTORY_SIZE,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_entry(
    method="GET",
    url="http://example.com/",
    status=200,
    intercepted=False,
    modified=False,
    notes="",
    body="",
    resp_body="OK",
):
    """Build a ProxyHistoryEntry for test convenience."""
    req = ProxyRequest(method=method, url=url, body=body, client_address="127.0.0.1:9999")
    resp = ProxyResponse(status_code=status, body=resp_body, elapsed=0.01)
    return ProxyHistoryEntry(request=req, response=resp, intercepted=intercepted, modified=modified, notes=notes)


# ---------------------------------------------------------------------------
# ProxyRequest / ProxyResponse / ProxyHistoryEntry dataclass tests
# ---------------------------------------------------------------------------


class TestProxyRequest(unittest.TestCase):

    def test_defaults(self):
        r = ProxyRequest()
        self.assertIsInstance(r.id, str)
        self.assertEqual(r.method, "")
        self.assertEqual(r.url, "")
        self.assertIsInstance(r.headers, dict)
        self.assertEqual(r.body, "")
        self.assertIsInstance(r.timestamp, str)
        self.assertEqual(r.client_address, "")

    def test_custom_values(self):
        r = ProxyRequest(
            method="POST", url="http://a.com", headers={"X-A": "1"}, body="hello", client_address="10.0.0.1:80"
        )
        self.assertEqual(r.method, "POST")
        self.assertEqual(r.url, "http://a.com")
        self.assertEqual(r.headers, {"X-A": "1"})
        self.assertEqual(r.body, "hello")
        self.assertEqual(r.client_address, "10.0.0.1:80")

    def test_unique_ids(self):
        ids = {ProxyRequest().id for _ in range(50)}
        self.assertEqual(len(ids), 50)

    def test_timestamp_iso_format(self):
        r = ProxyRequest()
        # Should contain a 'T' separator typical of ISO format
        self.assertIn("T", r.timestamp)


class TestProxyResponse(unittest.TestCase):

    def test_defaults(self):
        r = ProxyResponse()
        self.assertEqual(r.status_code, 0)
        self.assertEqual(r.headers, {})
        self.assertEqual(r.body, "")
        self.assertEqual(r.elapsed, 0.0)

    def test_custom_values(self):
        r = ProxyResponse(status_code=404, headers={"X": "Y"}, body="nope", elapsed=1.23)
        self.assertEqual(r.status_code, 404)
        self.assertEqual(r.body, "nope")
        self.assertAlmostEqual(r.elapsed, 1.23)


class TestProxyHistoryEntry(unittest.TestCase):

    def test_defaults(self):
        e = ProxyHistoryEntry()
        self.assertIsInstance(e.request, ProxyRequest)
        self.assertIsNone(e.response)
        self.assertFalse(e.intercepted)
        self.assertFalse(e.modified)
        self.assertEqual(e.notes, "")

    def test_with_response(self):
        resp = ProxyResponse(status_code=200, body="ok")
        e = ProxyHistoryEntry(response=resp, intercepted=True, modified=True, notes="test")
        self.assertEqual(e.response.status_code, 200)
        self.assertTrue(e.intercepted)
        self.assertTrue(e.modified)
        self.assertEqual(e.notes, "test")


# ---------------------------------------------------------------------------
# _PendingIntercept internal class
# ---------------------------------------------------------------------------


class TestPendingIntercept(unittest.TestCase):

    def test_creation(self):
        req = ProxyRequest(method="GET", url="http://x.com")
        pi = _PendingIntercept(req)
        self.assertIs(pi.proxy_request, req)
        self.assertIsInstance(pi.event, threading.Event)
        self.assertIsNone(pi.action)
        self.assertIsNone(pi.modified_request)

    def test_event_starts_unset(self):
        pi = _PendingIntercept(ProxyRequest())
        self.assertFalse(pi.event.is_set())


# ---------------------------------------------------------------------------
# InterceptProxy - initialisation & lifecycle (all sockets mocked)
# ---------------------------------------------------------------------------


class TestInterceptProxyInit(unittest.TestCase):

    def test_defaults(self):
        p = InterceptProxy()
        self.assertEqual(p.host, "127.0.0.1")
        self.assertEqual(p.port, 8080)
        self.assertFalse(p._intercept_enabled)
        self.assertFalse(p.is_running)

    def test_custom_params(self):
        p = InterceptProxy(host="0.0.0.0", port=9090, intercept=True)
        self.assertEqual(p.host, "0.0.0.0")
        self.assertEqual(p.port, 9090)
        self.assertTrue(p._intercept_enabled)

    @patch("core.proxy._ReusableTCPServer")
    def test_start_creates_server_and_thread(self, MockServer):
        server_instance = MagicMock()
        MockServer.return_value = server_instance

        p = InterceptProxy()
        p.start()

        MockServer.assert_called_once_with(("127.0.0.1", 8080), _ProxyHandler)
        self.assertTrue(p.is_running)
        self.assertIsNotNone(p._thread)

        # Cleanup
        p._thread.join(timeout=2)
        p._running = False

    @patch("core.proxy._ReusableTCPServer")
    def test_start_idempotent(self, MockServer):
        server_instance = MagicMock()
        MockServer.return_value = server_instance

        p = InterceptProxy()
        p.start()
        p.start()  # second call should be no-op
        MockServer.assert_called_once()

        p._running = False
        if p._thread and p._thread.is_alive():
            p._thread.join(timeout=2)

    @patch("core.proxy._ReusableTCPServer")
    def test_stop(self, MockServer):
        server_instance = MagicMock()
        MockServer.return_value = server_instance

        p = InterceptProxy()
        p.start()
        # Give thread a moment
        p._thread.join(timeout=1)
        p.stop()

        server_instance.shutdown.assert_called_once()
        server_instance.server_close.assert_called_once()
        self.assertFalse(p.is_running)
        self.assertIsNone(p._server)
        self.assertIsNone(p._thread)

    @patch("core.proxy._ReusableTCPServer")
    def test_stop_idempotent(self, MockServer):
        MockServer.return_value = MagicMock()
        p = InterceptProxy()
        p.stop()  # not running – should be safe
        self.assertFalse(p.is_running)

    @patch("core.proxy._ReusableTCPServer")
    def test_stop_releases_pending(self, MockServer):
        MockServer.return_value = MagicMock()
        p = InterceptProxy(intercept=True)
        p.start()

        req = ProxyRequest()
        pending = _PendingIntercept(req)
        p._pending_requests[req.id] = pending

        p.stop()
        self.assertTrue(pending.event.is_set())
        self.assertEqual(pending.action, "forward")
        self.assertEqual(len(p._pending_requests), 0)


# ---------------------------------------------------------------------------
# Intercept controls
# ---------------------------------------------------------------------------


class TestInterceptControls(unittest.TestCase):

    def setUp(self):
        self.proxy = InterceptProxy(intercept=False)

    def test_set_intercept_enable(self):
        self.proxy.set_intercept(True)
        self.assertTrue(self.proxy._intercept_enabled)

    def test_set_intercept_disable(self):
        self.proxy._intercept_enabled = True
        self.proxy.set_intercept(False)
        self.assertFalse(self.proxy._intercept_enabled)

    def test_disable_intercept_forwards_pending(self):
        req = ProxyRequest()
        pending = _PendingIntercept(req)
        self.proxy._pending_requests[req.id] = pending
        self.proxy._intercept_enabled = True

        self.proxy.set_intercept(False)

        self.assertTrue(pending.event.is_set())
        self.assertEqual(pending.action, "forward")
        self.assertEqual(len(self.proxy._pending_requests), 0)

    def test_get_pending_request_none_when_empty(self):
        self.assertIsNone(self.proxy.get_pending_request())

    def test_get_pending_request_returns_first_unresolved(self):
        req = ProxyRequest(method="POST", url="http://test.com")
        pending = _PendingIntercept(req)
        self.proxy._pending_requests[req.id] = pending

        got = self.proxy.get_pending_request()
        self.assertIs(got, req)

    def test_get_pending_request_skips_resolved(self):
        req1 = ProxyRequest(url="http://a.com")
        p1 = _PendingIntercept(req1)
        p1.event.set()  # already resolved

        req2 = ProxyRequest(url="http://b.com")
        p2 = _PendingIntercept(req2)

        self.proxy._pending_requests[req1.id] = p1
        self.proxy._pending_requests[req2.id] = p2

        got = self.proxy.get_pending_request()
        self.assertIs(got, req2)

    def test_forward_request(self):
        req = ProxyRequest()
        pending = _PendingIntercept(req)
        self.proxy._pending_requests[req.id] = pending

        self.proxy.forward_request(req.id)
        self.assertTrue(pending.event.is_set())
        self.assertEqual(pending.action, "forward")
        self.assertNotIn(req.id, self.proxy._pending_requests)

    def test_forward_request_with_modification(self):
        req = ProxyRequest(method="GET", url="http://old.com")
        pending = _PendingIntercept(req)
        self.proxy._pending_requests[req.id] = pending

        mod = {"method": "POST", "url": "http://new.com"}
        self.proxy.forward_request(req.id, modified_request=mod)
        self.assertEqual(pending.modified_request, mod)

    def test_forward_request_missing_id(self):
        with self.assertRaises(KeyError):
            self.proxy.forward_request("nonexistent-id")

    def test_drop_request(self):
        req = ProxyRequest()
        pending = _PendingIntercept(req)
        self.proxy._pending_requests[req.id] = pending

        self.proxy.drop_request(req.id)
        self.assertTrue(pending.event.is_set())
        self.assertEqual(pending.action, "drop")

    def test_drop_request_missing_id(self):
        with self.assertRaises(KeyError):
            self.proxy.drop_request("nonexistent-id")


# ---------------------------------------------------------------------------
# History management
# ---------------------------------------------------------------------------


class TestHistory(unittest.TestCase):

    def setUp(self):
        self.proxy = InterceptProxy()

    def test_empty_history(self):
        self.assertEqual(self.proxy.get_history(), [])

    def test_add_and_get_history(self):
        entry = _make_entry()
        self.proxy._add_history(entry)
        hist = self.proxy.get_history()
        self.assertEqual(len(hist), 1)
        self.assertIs(hist[0], entry)

    def test_history_returns_copy(self):
        self.proxy._add_history(_make_entry())
        h1 = self.proxy.get_history()
        h2 = self.proxy.get_history()
        self.assertIsNot(h1, h2)

    def test_clear_history(self):
        for _ in range(5):
            self.proxy._add_history(_make_entry())
        self.proxy.clear_history()
        self.assertEqual(len(self.proxy.get_history()), 0)

    def test_history_cap(self):
        for i in range(MAX_HISTORY_SIZE + 10):
            self.proxy._add_history(_make_entry(url=f"http://x.com/{i}"))
        self.assertLessEqual(len(self.proxy.get_history()), MAX_HISTORY_SIZE)


# ---------------------------------------------------------------------------
# History filtering
# ---------------------------------------------------------------------------


class TestHistoryFiltering(unittest.TestCase):

    def setUp(self):
        self.proxy = InterceptProxy()
        self.proxy._add_history(_make_entry(method="GET", url="http://a.com/foo", status=200))
        self.proxy._add_history(_make_entry(method="POST", url="http://b.com/bar", status=404))
        self.proxy._add_history(_make_entry(method="GET", url="http://a.com/baz", status=200))

    def test_filter_by_url(self):
        results = self.proxy.filter_history(url_pattern=r"a\.com")
        self.assertEqual(len(results), 2)

    def test_filter_by_method(self):
        results = self.proxy.filter_history(method="POST")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].request.method, "POST")

    def test_filter_by_status(self):
        results = self.proxy.filter_history(status_code=404)
        self.assertEqual(len(results), 1)

    def test_filter_combined(self):
        results = self.proxy.filter_history(url_pattern=r"a\.com", method="GET", status_code=200)
        self.assertEqual(len(results), 2)

    def test_filter_no_match(self):
        results = self.proxy.filter_history(url_pattern="zzz")
        self.assertEqual(len(results), 0)

    def test_filter_dropped_entry_excluded_by_status(self):
        dropped = ProxyHistoryEntry(
            request=ProxyRequest(method="GET", url="http://c.com/drop"),
            response=None,
        )
        self.proxy._add_history(dropped)
        results = self.proxy.filter_history(status_code=200)
        self.assertNotIn(dropped, results)


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


class TestExport(unittest.TestCase):

    def setUp(self):
        self.proxy = InterceptProxy()

    def test_export_empty(self):
        data = json.loads(self.proxy.export_history())
        self.assertEqual(data, [])

    def test_export_with_entries(self):
        self.proxy._add_history(_make_entry(method="GET", url="http://x.com"))
        raw = self.proxy.export_history(format="json")
        data = json.loads(raw)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["request"]["method"], "GET")
        self.assertIn("response", data[0])

    def test_export_dropped_entry(self):
        dropped = ProxyHistoryEntry(
            request=ProxyRequest(method="DELETE", url="http://x.com"),
            response=None,
            notes="dropped",
        )
        self.proxy._add_history(dropped)
        data = json.loads(self.proxy.export_history())
        self.assertIsNone(data[0]["response"])
        self.assertEqual(data[0]["notes"], "dropped")

    def test_export_structure(self):
        self.proxy._add_history(_make_entry())
        data = json.loads(self.proxy.export_history())[0]
        self.assertIn("request", data)
        self.assertIn("response", data)
        self.assertIn("intercepted", data)
        self.assertIn("modified", data)
        self.assertIn("notes", data)
        req = data["request"]
        for key in ("id", "method", "url", "headers", "body", "timestamp", "client_address"):
            self.assertIn(key, req)


# ---------------------------------------------------------------------------
# Rules engine
# ---------------------------------------------------------------------------


class TestRequestRules(unittest.TestCase):

    def setUp(self):
        self.proxy = InterceptProxy()

    def test_add_valid_rule(self):
        rule = {"match": r"old", "replace": "new", "scope": "url"}
        self.proxy.add_request_rule(rule)
        self.assertEqual(len(self.proxy._request_rules), 1)

    def test_add_rule_missing_key(self):
        with self.assertRaises(ValueError):
            self.proxy.add_request_rule({"match": "x", "replace": "y"})

    def test_add_rule_invalid_scope(self):
        with self.assertRaises(ValueError):
            self.proxy.add_request_rule({"match": "x", "replace": "y", "scope": "cookie"})

    def test_apply_url_rule(self):
        self.proxy.add_request_rule({"match": r"old", "replace": "new", "scope": "url"})
        req = ProxyRequest(url="http://old.com/path")
        modified = self.proxy._apply_request_rules(req)
        self.assertTrue(modified)
        self.assertEqual(req.url, "http://new.com/path")

    def test_apply_header_rule(self):
        self.proxy.add_request_rule({"match": r"BadToken", "replace": "GoodToken", "scope": "header"})
        req = ProxyRequest(headers={"Authorization": "Bearer BadToken"})
        modified = self.proxy._apply_request_rules(req)
        self.assertTrue(modified)
        self.assertEqual(req.headers["Authorization"], "Bearer GoodToken")

    def test_apply_body_rule(self):
        self.proxy.add_request_rule({"match": r"secret", "replace": "REDACTED", "scope": "body"})
        req = ProxyRequest(body="my secret data")
        modified = self.proxy._apply_request_rules(req)
        self.assertTrue(modified)
        self.assertEqual(req.body, "my REDACTED data")

    def test_no_match_returns_false(self):
        self.proxy.add_request_rule({"match": r"zzz", "replace": "aaa", "scope": "url"})
        req = ProxyRequest(url="http://example.com")
        self.assertFalse(self.proxy._apply_request_rules(req))


class TestResponseRules(unittest.TestCase):

    def setUp(self):
        self.proxy = InterceptProxy()

    def test_add_valid_response_rule(self):
        rule = {"match": r"old", "replace": "new", "scope": "body"}
        self.proxy.add_response_rule(rule)
        self.assertEqual(len(self.proxy._response_rules), 1)

    def test_add_response_rule_invalid_scope(self):
        with self.assertRaises(ValueError):
            self.proxy.add_response_rule({"match": "x", "replace": "y", "scope": "url"})

    def test_apply_body_response_rule(self):
        self.proxy.add_response_rule({"match": r"password", "replace": "***", "scope": "body"})
        resp = ProxyResponse(body="your password is here")
        modified = self.proxy._apply_response_rules(resp)
        self.assertTrue(modified)
        self.assertEqual(resp.body, "your *** is here")

    def test_apply_header_response_rule(self):
        self.proxy.add_response_rule({"match": r"private", "replace": "public", "scope": "header"})
        resp = ProxyResponse(headers={"Cache-Control": "private, no-store"})
        modified = self.proxy._apply_response_rules(resp)
        self.assertTrue(modified)
        self.assertEqual(resp.headers["Cache-Control"], "public, no-store")

    def test_apply_status_response_rule(self):
        self.proxy.add_response_rule({"match": r".*", "replace": "200", "scope": "status"})
        resp = ProxyResponse(status_code=500)
        modified = self.proxy._apply_response_rules(resp)
        self.assertTrue(modified)
        self.assertEqual(resp.status_code, 200)

    def test_status_rule_invalid_replacement(self):
        self.proxy.add_response_rule({"match": r".*", "replace": "not_a_number", "scope": "status"})
        resp = ProxyResponse(status_code=500)
        modified = self.proxy._apply_response_rules(resp)
        self.assertFalse(modified)
        self.assertEqual(resp.status_code, 500)

    def test_clear_rules(self):
        self.proxy.add_request_rule({"match": "a", "replace": "b", "scope": "url"})
        self.proxy.add_response_rule({"match": "c", "replace": "d", "scope": "body"})
        self.proxy.clear_rules()
        self.assertEqual(len(self.proxy._request_rules), 0)
        self.assertEqual(len(self.proxy._response_rules), 0)


# ---------------------------------------------------------------------------
# Upstream forwarding (mocked)
# ---------------------------------------------------------------------------


class TestForwardUpstream(unittest.TestCase):

    def setUp(self):
        self.proxy = InterceptProxy()

    @patch("core.proxy.urllib.request.urlopen")
    def test_forward_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b"OK"
        mock_resp.getheaders.return_value = [("Content-Type", "text/html")]
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        req = ProxyRequest(method="GET", url="http://example.com/", headers={"Accept": "*/*"})
        result = self.proxy._forward_upstream(req)
        self.assertEqual(result["status"], 200)
        self.assertEqual(result["body"], "OK")

    @patch("core.proxy.urllib.request.urlopen")
    def test_forward_http_error(self, mock_urlopen):
        import urllib.error

        err = urllib.error.HTTPError(
            url="http://x.com",
            code=403,
            msg="Forbidden",
            hdrs=MagicMock(),
            fp=MagicMock(),
        )
        err.read = MagicMock(return_value=b"denied")
        err.headers = {"X-Err": "yes"}
        mock_urlopen.side_effect = err

        req = ProxyRequest(method="GET", url="http://x.com")
        result = self.proxy._forward_upstream(req)
        self.assertEqual(result["status"], 403)
        self.assertIn("denied", result["body"])


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases(unittest.TestCase):

    def test_rule_stored_as_copy(self):
        proxy = InterceptProxy()
        rule = {"match": "a", "replace": "b", "scope": "url"}
        proxy.add_request_rule(rule)
        rule["match"] = "changed"
        self.assertEqual(proxy._request_rules[0]["match"], "a")

    def test_multiple_rules_applied_in_order(self):
        proxy = InterceptProxy()
        proxy.add_request_rule({"match": r"a", "replace": "b", "scope": "url"})
        proxy.add_request_rule({"match": r"b", "replace": "c", "scope": "url"})
        req = ProxyRequest(url="http://a.com")
        proxy._apply_request_rules(req)
        self.assertEqual(req.url, "http://c.com")

    def test_is_running_property(self):
        proxy = InterceptProxy()
        self.assertFalse(proxy.is_running)
        proxy._running = True
        self.assertTrue(proxy.is_running)

    def test_add_response_rule_missing_key(self):
        proxy = InterceptProxy()
        with self.assertRaises(ValueError):
            proxy.add_response_rule({"match": "x"})

    def test_filter_method_case_insensitive_input(self):
        proxy = InterceptProxy()
        proxy._add_history(_make_entry(method="GET", url="http://x.com"))
        results = proxy.filter_history(method="get")
        self.assertEqual(len(results), 1)


if __name__ == "__main__":
    unittest.main()
