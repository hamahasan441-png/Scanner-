#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the Repeater module."""

import unittest
from unittest.mock import patch, MagicMock, PropertyMock

import requests

from core.repeater import Repeater, RepeaterResponse


# ------------------------------------------------------------------ #
#  Helper fixtures                                                    #
# ------------------------------------------------------------------ #

def _mock_response(status_code=200, headers=None, body=b"OK",
                   text="OK", url="http://example.com/",
                   cookies=None):
    """Build a mock that mimics a *requests.Response*."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = headers or {"Content-Type": "text/html"}
    resp.content = body
    resp.text = text
    resp.url = url
    resp.cookies = cookies or MagicMock(items=MagicMock(return_value=[]))
    return resp


# ------------------------------------------------------------------ #
#  Tests – RepeaterResponse                                           #
# ------------------------------------------------------------------ #

class TestRepeaterResponse(unittest.TestCase):
    """Tests for the RepeaterResponse data container."""

    def _make(self, **overrides):
        defaults = dict(
            status_code=200, headers={"X": "1"}, body="hello",
            elapsed=0.12, size=5, cookies={}, url="http://a.com/",
            method="GET", request_headers={}, request_body=None,
            timestamp="2024-01-01T00:00:00+00:00",
        )
        defaults.update(overrides)
        return RepeaterResponse(**defaults)

    def test_fields_stored(self):
        rr = self._make(status_code=201, body="created")
        self.assertEqual(rr.status_code, 201)
        self.assertEqual(rr.body, "created")

    def test_to_dict_keys(self):
        rr = self._make()
        d = rr.to_dict()
        expected = {
            "status_code", "headers", "body", "elapsed", "size",
            "cookies", "url", "method", "request_headers",
            "request_body", "timestamp",
        }
        self.assertEqual(set(d.keys()), expected)

    def test_to_dict_values(self):
        rr = self._make(elapsed=0.5, size=42)
        d = rr.to_dict()
        self.assertEqual(d["elapsed"], 0.5)
        self.assertEqual(d["size"], 42)


# ------------------------------------------------------------------ #
#  Tests – Repeater.__init__                                          #
# ------------------------------------------------------------------ #

class TestRepeaterInit(unittest.TestCase):
    """Initialisation and configuration."""

    def test_defaults(self):
        r = Repeater()
        self.assertEqual(r.timeout, 15)
        self.assertFalse(r.verify_ssl)
        self.assertEqual(r._history, [])

    def test_custom_timeout(self):
        r = Repeater(timeout=30)
        self.assertEqual(r.timeout, 30)

    def test_proxy_config(self):
        r = Repeater(proxy="http://127.0.0.1:8080")
        self.assertEqual(r.session.proxies["http"], "http://127.0.0.1:8080")
        self.assertEqual(r.session.proxies["https"], "http://127.0.0.1:8080")

    def test_verify_ssl_flag(self):
        r = Repeater(verify_ssl=True)
        self.assertTrue(r.verify_ssl)


# ------------------------------------------------------------------ #
#  Tests – send()                                                     #
# ------------------------------------------------------------------ #

class TestSend(unittest.TestCase):
    """Tests for Repeater.send."""

    def setUp(self):
        self.rep = Repeater()

    @patch.object(Repeater, '_build_response')
    def _send(self, mock_resp, build_resp, **kwargs):
        self.rep.session.request = MagicMock(return_value=mock_resp)
        rr = _mock_response()
        build_resp.return_value = RepeaterResponse(
            status_code=mock_resp.status_code,
            headers=dict(mock_resp.headers),
            body=mock_resp.text,
            elapsed=0.01, size=len(mock_resp.content),
            cookies={}, url=mock_resp.url,
            method=kwargs.get("method", "GET"),
            request_headers={}, request_body=None,
            timestamp="2024-01-01T00:00:00+00:00",
        )
        return self.rep.send(**kwargs)

    @patch("core.repeater.requests.Session.request")
    def test_get_request(self, mock_req):
        mock_req.return_value = _mock_response()
        rr = self.rep.send("GET", "http://example.com/")
        self.assertEqual(rr.status_code, 200)
        self.assertEqual(rr.method, "GET")

    @patch("core.repeater.requests.Session.request")
    def test_post_request(self, mock_req):
        mock_req.return_value = _mock_response(status_code=201, text="created",
                                                body=b"created")
        rr = self.rep.send("POST", "http://example.com/api",
                           body="data=1")
        self.assertEqual(rr.status_code, 201)
        self.assertEqual(rr.method, "POST")

    @patch("core.repeater.requests.Session.request")
    def test_put_request(self, mock_req):
        mock_req.return_value = _mock_response(status_code=204, text="",
                                                body=b"")
        rr = self.rep.send("PUT", "http://example.com/item/1",
                           body='{"key":"value"}')
        self.assertEqual(rr.status_code, 204)
        self.assertEqual(rr.method, "PUT")

    @patch("core.repeater.requests.Session.request")
    def test_delete_request(self, mock_req):
        mock_req.return_value = _mock_response(status_code=200, text="deleted",
                                                body=b"deleted")
        rr = self.rep.send("DELETE", "http://example.com/item/1")
        self.assertEqual(rr.status_code, 200)
        self.assertEqual(rr.method, "DELETE")

    @patch("core.repeater.requests.Session.request")
    def test_custom_headers(self, mock_req):
        mock_req.return_value = _mock_response()
        self.rep.send("GET", "http://example.com/",
                      headers={"Authorization": "Bearer tok"})
        _, kwargs = mock_req.call_args
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer tok")

    @patch("core.repeater.requests.Session.request")
    def test_params_forwarded(self, mock_req):
        mock_req.return_value = _mock_response()
        self.rep.send("GET", "http://example.com/search",
                      params={"q": "test"})
        _, kwargs = mock_req.call_args
        self.assertEqual(kwargs["params"], {"q": "test"})

    @patch("core.repeater.requests.Session.request")
    def test_cookies_forwarded(self, mock_req):
        mock_req.return_value = _mock_response()
        self.rep.send("GET", "http://example.com/",
                      cookies={"session": "abc123"})
        _, kwargs = mock_req.call_args
        self.assertEqual(kwargs["cookies"], {"session": "abc123"})

    @patch("core.repeater.requests.Session.request")
    def test_redirects_disabled(self, mock_req):
        mock_req.return_value = _mock_response(status_code=302)
        self.rep.send("GET", "http://example.com/old",
                      allow_redirects=False)
        _, kwargs = mock_req.call_args
        self.assertFalse(kwargs["allow_redirects"])

    @patch("core.repeater.requests.Session.request")
    def test_timeout_passed(self, mock_req):
        mock_req.return_value = _mock_response()
        rep = Repeater(timeout=5)
        rep.send("GET", "http://example.com/")
        _, kwargs = mock_req.call_args
        self.assertEqual(kwargs["timeout"], 5)

    @patch("core.repeater.requests.Session.request")
    def test_method_uppercased(self, mock_req):
        mock_req.return_value = _mock_response()
        rr = self.rep.send("get", "http://example.com/")
        self.assertEqual(rr.method, "GET")

    @patch("core.repeater.requests.Session.request")
    def test_connection_error(self, mock_req):
        mock_req.side_effect = requests.ConnectionError("refused")
        with self.assertRaises(requests.ConnectionError):
            self.rep.send("GET", "http://unreachable.example.com/")

    @patch("core.repeater.requests.Session.request")
    def test_timeout_error(self, mock_req):
        mock_req.side_effect = requests.Timeout("timed out")
        with self.assertRaises(requests.Timeout):
            self.rep.send("GET", "http://slow.example.com/")

    @patch("core.repeater.requests.Session.request")
    def test_response_cookies_captured(self, mock_req):
        cookie_jar = MagicMock()
        cookie_jar.items.return_value = [("sid", "xyz")]
        mock_req.return_value = _mock_response(cookies=cookie_jar)
        rr = self.rep.send("GET", "http://example.com/login")
        self.assertEqual(rr.cookies, {"sid": "xyz"})


# ------------------------------------------------------------------ #
#  Tests – parse_raw_request                                          #
# ------------------------------------------------------------------ #

class TestParseRawRequest(unittest.TestCase):
    """Tests for Repeater.parse_raw_request."""

    def test_simple_get(self):
        raw = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        method, path, headers, body = Repeater.parse_raw_request(raw)
        self.assertEqual(method, "GET")
        self.assertEqual(path, "/index.html")
        self.assertEqual(headers["Host"], "example.com")
        self.assertIsNone(body)

    def test_post_with_body(self):
        raw = ("POST /login HTTP/1.1\r\n"
               "Host: example.com\r\n"
               "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
               "user=admin&pass=secret")
        method, path, headers, body = Repeater.parse_raw_request(raw)
        self.assertEqual(method, "POST")
        self.assertEqual(body, "user=admin&pass=secret")

    def test_unix_line_endings(self):
        raw = "GET / HTTP/1.1\nHost: h.com\n\nbody"
        method, path, headers, body = Repeater.parse_raw_request(raw)
        self.assertEqual(method, "GET")
        self.assertEqual(headers["Host"], "h.com")
        self.assertEqual(body, "body")

    def test_no_body_section(self):
        raw = "HEAD / HTTP/1.1\r\nHost: example.com"
        method, path, headers, body = Repeater.parse_raw_request(raw)
        self.assertEqual(method, "HEAD")
        self.assertIsNone(body)

    def test_multiple_headers(self):
        raw = ("GET / HTTP/1.1\r\n"
               "Host: example.com\r\n"
               "Accept: text/html\r\n"
               "Cookie: a=1\r\n\r\n")
        _, _, headers, _ = Repeater.parse_raw_request(raw)
        self.assertEqual(headers["Accept"], "text/html")
        self.assertEqual(headers["Cookie"], "a=1")

    def test_empty_body_treated_as_none(self):
        raw = "GET / HTTP/1.1\r\nHost: h\r\n\r\n   "
        _, _, _, body = Repeater.parse_raw_request(raw)
        self.assertIsNone(body)


# ------------------------------------------------------------------ #
#  Tests – build_raw_request                                          #
# ------------------------------------------------------------------ #

class TestBuildRawRequest(unittest.TestCase):
    """Tests for Repeater.build_raw_request."""

    def test_basic_build(self):
        raw = Repeater.build_raw_request("GET", "http://example.com/page")
        self.assertIn("GET /page HTTP/1.1", raw)
        self.assertIn("Host: example.com", raw)

    def test_root_path(self):
        raw = Repeater.build_raw_request("GET", "http://example.com")
        self.assertIn("GET / HTTP/1.1", raw)

    def test_query_string_preserved(self):
        raw = Repeater.build_raw_request("GET", "http://example.com/s?q=x")
        self.assertIn("GET /s?q=x HTTP/1.1", raw)

    def test_custom_headers(self):
        raw = Repeater.build_raw_request(
            "POST", "http://example.com/api",
            headers={"Content-Type": "application/json"},
        )
        self.assertIn("Content-Type: application/json", raw)

    def test_body_appended(self):
        raw = Repeater.build_raw_request(
            "POST", "http://example.com/api",
            body='{"key":"val"}',
        )
        self.assertTrue(raw.endswith('{"key":"val"}'))


# ------------------------------------------------------------------ #
#  Tests – send_raw                                                   #
# ------------------------------------------------------------------ #

class TestSendRaw(unittest.TestCase):
    """Tests for Repeater.send_raw."""

    def setUp(self):
        self.rep = Repeater()

    @patch("core.repeater.requests.Session.request")
    def test_send_raw_basic(self, mock_req):
        mock_req.return_value = _mock_response()
        raw = "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n"
        rr = self.rep.send_raw(raw)
        self.assertEqual(rr.status_code, 200)
        _, kwargs = mock_req.call_args
        self.assertIn("example.com", kwargs["url"])

    @patch("core.repeater.requests.Session.request")
    def test_send_raw_host_override(self, mock_req):
        mock_req.return_value = _mock_response()
        raw = "GET / HTTP/1.1\r\nHost: old.com\r\n\r\n"
        self.rep.send_raw(raw, host="new.com")
        _, kwargs = mock_req.call_args
        self.assertIn("new.com", kwargs["url"])

    @patch("core.repeater.requests.Session.request")
    def test_send_raw_ssl(self, mock_req):
        mock_req.return_value = _mock_response()
        raw = "GET / HTTP/1.1\r\nHost: secure.com\r\n\r\n"
        self.rep.send_raw(raw, use_ssl=True)
        _, kwargs = mock_req.call_args
        self.assertTrue(kwargs["url"].startswith("https://"))

    @patch("core.repeater.requests.Session.request")
    def test_send_raw_custom_port(self, mock_req):
        mock_req.return_value = _mock_response()
        raw = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        self.rep.send_raw(raw, port=8443, use_ssl=True)
        _, kwargs = mock_req.call_args
        self.assertIn(":8443", kwargs["url"])


# ------------------------------------------------------------------ #
#  Tests – history                                                    #
# ------------------------------------------------------------------ #

class TestHistory(unittest.TestCase):
    """Tests for history tracking."""

    def setUp(self):
        self.rep = Repeater()

    @patch("core.repeater.requests.Session.request")
    def test_history_populated(self, mock_req):
        mock_req.return_value = _mock_response()
        self.rep.send("GET", "http://example.com/")
        self.assertEqual(len(self.rep.history), 1)

    @patch("core.repeater.requests.Session.request")
    def test_history_multiple(self, mock_req):
        mock_req.return_value = _mock_response()
        self.rep.send("GET", "http://a.com/")
        self.rep.send("POST", "http://b.com/")
        self.assertEqual(len(self.rep.history), 2)

    @patch("core.repeater.requests.Session.request")
    def test_history_is_copy(self, mock_req):
        """Modifying the returned list must not affect internal state."""
        mock_req.return_value = _mock_response()
        self.rep.send("GET", "http://example.com/")
        h = self.rep.history
        h.clear()
        self.assertEqual(len(self.rep.history), 1)

    @patch("core.repeater.requests.Session.request")
    def test_clear_history(self, mock_req):
        mock_req.return_value = _mock_response()
        self.rep.send("GET", "http://example.com/")
        self.rep.clear_history()
        self.assertEqual(len(self.rep.history), 0)

    @patch("core.repeater.requests.Session.request")
    def test_history_tuple_structure(self, mock_req):
        mock_req.return_value = _mock_response()
        self.rep.send("GET", "http://example.com/path")
        req_info, rr = self.rep.history[0]
        self.assertEqual(req_info["method"], "GET")
        self.assertEqual(req_info["url"], "http://example.com/path")
        self.assertIsInstance(rr, RepeaterResponse)


# ------------------------------------------------------------------ #
#  Tests – replay                                                     #
# ------------------------------------------------------------------ #

class TestReplay(unittest.TestCase):
    """Tests for Repeater.replay."""

    def setUp(self):
        self.rep = Repeater()

    @patch("core.repeater.requests.Session.request")
    def test_basic_replay(self, mock_req):
        mock_req.return_value = _mock_response()
        self.rep.send("GET", "http://example.com/page")
        rr = self.rep.replay(0)
        self.assertEqual(rr.status_code, 200)
        self.assertEqual(len(self.rep.history), 2)

    @patch("core.repeater.requests.Session.request")
    def test_replay_with_header_modification(self, mock_req):
        mock_req.return_value = _mock_response()
        self.rep.send("GET", "http://example.com/")
        self.rep.replay(0, modifications={"headers": {"X-Custom": "yes"}})
        _, kwargs = mock_req.call_args
        self.assertEqual(kwargs["headers"]["X-Custom"], "yes")

    @patch("core.repeater.requests.Session.request")
    def test_replay_with_body_modification(self, mock_req):
        mock_req.return_value = _mock_response()
        self.rep.send("POST", "http://example.com/api", body="old")
        self.rep.replay(0, modifications={"body": "new"})
        _, kwargs = mock_req.call_args
        self.assertEqual(kwargs["data"], "new")

    @patch("core.repeater.requests.Session.request")
    def test_replay_with_method_change(self, mock_req):
        mock_req.return_value = _mock_response()
        self.rep.send("GET", "http://example.com/")
        rr = self.rep.replay(0, modifications={"method": "POST"})
        self.assertEqual(rr.method, "POST")

    @patch("core.repeater.requests.Session.request")
    def test_replay_with_url_change(self, mock_req):
        mock_req.return_value = _mock_response()
        self.rep.send("GET", "http://example.com/a")
        self.rep.replay(0, modifications={"url": "http://example.com/b"})
        _, kwargs = mock_req.call_args
        self.assertEqual(kwargs["url"], "http://example.com/b")

    def test_replay_invalid_index(self):
        with self.assertRaises(IndexError):
            self.rep.replay(0)

    def test_replay_negative_index(self):
        with self.assertRaises(IndexError):
            self.rep.replay(-1)


# ------------------------------------------------------------------ #
#  Tests – diff_responses                                             #
# ------------------------------------------------------------------ #

class TestDiffResponses(unittest.TestCase):
    """Tests for Repeater.diff_responses."""

    def setUp(self):
        self.rep = Repeater()

    @patch("core.repeater.requests.Session.request")
    def test_diff_identical(self, mock_req):
        mock_req.return_value = _mock_response()
        self.rep.send("GET", "http://example.com/")
        self.rep.send("GET", "http://example.com/")
        diff = self.rep.diff_responses(0, 1)
        self.assertIn("status", diff)

    @patch("core.repeater.requests.Session.request")
    def test_diff_different_status(self, mock_req):
        mock_req.return_value = _mock_response(status_code=200)
        self.rep.send("GET", "http://example.com/a")
        mock_req.return_value = _mock_response(status_code=404, text="nope",
                                                body=b"nope")
        self.rep.send("GET", "http://example.com/b")
        diff = self.rep.diff_responses(0, 1)
        self.assertIn("status", diff)

    def test_diff_invalid_index(self):
        with self.assertRaises(IndexError):
            self.rep.diff_responses(0, 1)

    @patch("core.repeater.requests.Session.request")
    def test_diff_invalid_second_index(self, mock_req):
        mock_req.return_value = _mock_response()
        self.rep.send("GET", "http://example.com/")
        with self.assertRaises(IndexError):
            self.rep.diff_responses(0, 5)

    @patch("core.repeater.requests.Session.request")
    def test_diff_fallback_without_comparer(self, mock_req):
        """When the Comparer import fails the basic diff is used."""
        mock_req.return_value = _mock_response()
        self.rep.send("GET", "http://example.com/")
        self.rep.send("GET", "http://example.com/")
        with patch.dict("sys.modules", {"utils.comparer": None}):
            diff = self.rep.diff_responses(0, 1)
        self.assertIn("status", diff)


# ------------------------------------------------------------------ #
#  Tests – error handling                                             #
# ------------------------------------------------------------------ #

class TestErrorHandling(unittest.TestCase):
    """Edge-cases and error scenarios."""

    def setUp(self):
        self.rep = Repeater()

    @patch("core.repeater.requests.Session.request")
    def test_ssl_error(self, mock_req):
        mock_req.side_effect = requests.exceptions.SSLError("cert fail")
        with self.assertRaises(requests.exceptions.SSLError):
            self.rep.send("GET", "https://bad-cert.example.com/")

    @patch("core.repeater.requests.Session.request")
    def test_too_many_redirects(self, mock_req):
        mock_req.side_effect = requests.exceptions.TooManyRedirects()
        with self.assertRaises(requests.exceptions.TooManyRedirects):
            self.rep.send("GET", "http://loop.example.com/")

    @patch("core.repeater.requests.Session.request")
    def test_response_elapsed_positive(self, mock_req):
        mock_req.return_value = _mock_response()
        rr = self.rep.send("GET", "http://example.com/")
        self.assertGreaterEqual(rr.elapsed, 0)

    @patch("core.repeater.requests.Session.request")
    def test_response_timestamp_iso(self, mock_req):
        mock_req.return_value = _mock_response()
        rr = self.rep.send("GET", "http://example.com/")
        self.assertIn("T", rr.timestamp)

    @patch("core.repeater.requests.Session.request")
    def test_patch_method(self, mock_req):
        mock_req.return_value = _mock_response()
        rr = self.rep.send("PATCH", "http://example.com/item/1",
                           body='{"name":"new"}')
        self.assertEqual(rr.method, "PATCH")


# ------------------------------------------------------------------ #
#  Tests – proxy configuration                                       #
# ------------------------------------------------------------------ #

class TestProxyConfiguration(unittest.TestCase):
    """Tests for proxy support."""

    def test_no_proxy_by_default(self):
        r = Repeater()
        self.assertFalse(r.session.proxies)

    def test_socks_proxy(self):
        r = Repeater(proxy="socks5://127.0.0.1:9050")
        self.assertEqual(r.session.proxies["http"], "socks5://127.0.0.1:9050")

    @patch("core.repeater.requests.Session.request")
    def test_proxy_used_in_requests(self, mock_req):
        mock_req.return_value = _mock_response()
        r = Repeater(proxy="http://proxy:8080")
        r.send("GET", "http://example.com/")
        self.assertEqual(r.session.proxies["http"], "http://proxy:8080")


if __name__ == "__main__":
    unittest.main()
