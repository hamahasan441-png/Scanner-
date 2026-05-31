"""Tests for tests/fixtures.py - Shared test fixtures module."""
from __future__ import annotations

import importlib.util
import os
import sys

# Load tests/fixtures.py without importing the full package tree
_spec = importlib.util.spec_from_file_location(
    "tests.fixtures",
    os.path.join(os.path.dirname(__file__), "fixtures.py"),
)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["tests.fixtures"] = _mod
_spec.loader.exec_module(_mod)

MockResponse = _mod.MockResponse
MockRequester = _mod.MockRequester
MockEngine = _mod.MockEngine
make_response = _mod.make_response
make_engine = _mod.make_engine


class TestMockResponse:
    """Tests for MockResponse class."""

    def test_default_attributes(self) -> None:
        r = MockResponse()
        assert r.text == ""
        assert r.status_code == 200
        assert r.headers == {}
        assert r.url == "http://example.com"
        assert r.content == b""

    def test_custom_text_and_status(self) -> None:
        r = MockResponse(text="<html>hello</html>", status_code=404)
        assert r.text == "<html>hello</html>"
        assert r.status_code == 404
        assert r.content == b"<html>hello</html>"

    def test_custom_headers(self) -> None:
        hdrs = {"Content-Type": "text/html", "X-Custom": "value"}
        r = MockResponse(headers=hdrs)
        assert r.headers == hdrs
        assert r.headers["Content-Type"] == "text/html"

    def test_elapsed_attribute(self) -> None:
        r = MockResponse()
        assert r.elapsed.total_seconds() == 0.1


class TestMockRequester:
    """Tests for MockRequester class."""

    def test_returns_responses_in_order(self) -> None:
        r1 = MockResponse(text="first", status_code=200)
        r2 = MockResponse(text="second", status_code=301)
        req = MockRequester(responses=[r1, r2])
        assert req.request("http://a.com") is r1
        assert req.request("http://b.com") is r2

    def test_returns_none_when_exhausted(self) -> None:
        r1 = MockResponse(text="only")
        req = MockRequester(responses=[r1])
        assert req.request("http://a.com") is r1
        assert req.request("http://a.com") is None

    def test_call_count_increments(self) -> None:
        req = MockRequester(responses=[MockResponse()])
        assert req.call_count == 0
        req.request("http://a.com")
        assert req.call_count == 1
        req.request("http://b.com")
        assert req.call_count == 2

    def test_call_log_records_requests(self) -> None:
        req = MockRequester(responses=[MockResponse(), MockResponse()])
        req.request("http://target.com/path", method="POST", data="x=1")
        assert len(req.call_log) == 1
        entry = req.call_log[0]
        assert entry["url"] == "http://target.com/path"
        assert entry["method"] == "POST"
        assert entry["data"] == "x=1"

    def test_waf_bypass_encode_returns_list(self) -> None:
        req = MockRequester()
        result = req.waf_bypass_encode("<script>alert(1)</script>")
        assert isinstance(result, list)
        assert result == ["<script>alert(1)</script>"]

    def test_empty_responses_returns_none(self) -> None:
        req = MockRequester(responses=[])
        assert req.request("http://x.com") is None


class TestMockEngine:
    """Tests for MockEngine class."""

    def test_has_config_requester_findings(self) -> None:
        eng = MockEngine()
        assert isinstance(eng.config, dict)
        assert isinstance(eng.requester, MockRequester)
        assert isinstance(eng.findings, list)
        assert eng.findings == []

    def test_add_finding_appends(self) -> None:
        eng = MockEngine()
        eng.add_finding({"vuln": "xss", "url": "http://t.com"})
        eng.add_finding({"vuln": "sqli", "url": "http://t.com/login"})
        assert len(eng.findings) == 2
        assert eng.findings[0]["vuln"] == "xss"
        assert eng.findings[1]["vuln"] == "sqli"

    def test_custom_config(self) -> None:
        eng = MockEngine(config={"verbose": True, "threads": 10})
        assert eng.config["verbose"] is True
        assert eng.config["threads"] == 10

    def test_requester_uses_provided_responses(self) -> None:
        r = MockResponse(text="payload response", status_code=500)
        eng = MockEngine(responses=[r])
        resp = eng.requester.request("http://vuln.com")
        assert resp is r
        assert resp.status_code == 500

    def test_ai_attribute_is_none(self) -> None:
        eng = MockEngine()
        assert eng.ai is None


class TestFactoryFunctions:
    """Tests for make_response and make_engine factory functions."""

    def test_make_response_defaults(self) -> None:
        r = make_response()
        assert r.text == ""
        assert r.status_code == 200
        assert r.headers == {}

    def test_make_response_custom(self) -> None:
        r = make_response(text="OK", status_code=201, headers={"X-Id": "abc"})
        assert r.text == "OK"
        assert r.status_code == 201
        assert r.headers["X-Id"] == "abc"

    def test_make_engine_defaults(self) -> None:
        eng = make_engine()
        assert eng.config == {"verbose": False}
        assert eng.findings == []

    def test_make_engine_with_responses(self) -> None:
        r = make_response(text="test")
        eng = make_engine(responses=[r])
        resp = eng.requester.request("http://x.com")
        assert resp.text == "test"

    def test_make_engine_requester_is_mock_requester(self) -> None:
        eng = make_engine()
        assert isinstance(eng.requester, MockRequester)
