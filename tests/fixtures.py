"""ATOMIC FRAMEWORK - Shared Test Fixtures

Provides reusable mock objects for unit tests. Import these instead of
redefining _MockEngine/_MockRequester/_MockResponse in every test file.

Usage:
    from tests.fixtures import make_engine, make_response, MockEngine, MockRequester
"""
from __future__ import annotations

from typing import Any, Optional
from unittest.mock import MagicMock


class MockResponse:
    """Mock HTTP response matching the interface tests expect."""

    def __init__(
        self,
        text: str = "",
        status_code: int = 200,
        headers: Optional[dict[str, str]] = None,
        url: str = "http://example.com",
    ) -> None:
        self.text = text
        self.status_code = status_code
        self.headers: dict[str, str] = headers or {}
        self.url = url
        self.content: bytes = text.encode() if isinstance(text, str) else text
        self.elapsed = MagicMock()
        self.elapsed.total_seconds = MagicMock(return_value=0.1)


class MockRequester:
    """Mock requester that returns pre-configured responses in order."""

    def __init__(self, responses: Optional[list[MockResponse | None]] = None) -> None:
        self._responses: list[MockResponse | None] = responses or []
        self._call_idx: int = 0
        self.call_count: int = 0
        self.call_log: list[dict[str, Any]] = []

    def request(
        self,
        url: str,
        method: str = "GET",
        data: Any = None,
        headers: Optional[dict[str, str]] = None,
        allow_redirects: bool = True,
        **kwargs: Any,
    ) -> Optional[MockResponse]:
        self.call_count += 1
        self.call_log.append(
            {"url": url, "method": method, "data": data, "headers": headers}
        )
        if self._call_idx < len(self._responses):
            resp = self._responses[self._call_idx]
            self._call_idx += 1
            return resp
        return None

    def waf_bypass_encode(self, payload: str) -> list[str]:
        return [payload]


class MockEngine:
    """Mock scan engine matching the interface modules expect."""

    def __init__(
        self,
        responses: Optional[list[MockResponse | None]] = None,
        config: Optional[dict[str, Any]] = None,
    ) -> None:
        self.config: dict[str, Any] = config or {"verbose": False}
        self.requester = MockRequester(responses)
        self.findings: list[Any] = []
        self.ai = None

    def add_finding(self, finding: Any) -> None:
        self.findings.append(finding)


# Factory functions for convenience


def make_response(
    text: str = "",
    status_code: int = 200,
    headers: Optional[dict[str, str]] = None,
) -> MockResponse:
    """Create a MockResponse with given attributes."""
    return MockResponse(text=text, status_code=status_code, headers=headers)


def make_engine(
    responses: Optional[list[MockResponse | None]] = None,
    config: Optional[dict[str, Any]] = None,
) -> MockEngine:
    """Create a MockEngine with pre-configured responses."""
    return MockEngine(responses=responses, config=config)
