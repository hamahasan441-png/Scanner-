"""Tests for utils/exceptions.py - Custom exception hierarchy."""
from __future__ import annotations

import importlib.util
import os
import sys

# Load utils/exceptions.py without importing the full package tree
_spec = importlib.util.spec_from_file_location(
    "utils.exceptions",
    os.path.join(os.path.dirname(__file__), "..", "utils", "exceptions.py"),
)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["utils.exceptions"] = _mod
_spec.loader.exec_module(_mod)

AtomicError = _mod.AtomicError
NetworkError = _mod.NetworkError
ConnectionTimeoutError = _mod.ConnectionTimeoutError
ConnectionRefusedError = _mod.ConnectionRefusedError
SSLVerificationError = _mod.SSLVerificationError
RateLimitError = _mod.RateLimitError
WAFBlockError = _mod.WAFBlockError
ScanError = _mod.ScanError
ModuleLoadError = _mod.ModuleLoadError
ModuleExecutionError = _mod.ModuleExecutionError
PayloadError = _mod.PayloadError
ConfigError = _mod.ConfigError
InvalidTargetError = _mod.InvalidTargetError


class TestAtomicError:
    """Test the base AtomicError class."""

    def test_message_attribute(self) -> None:
        err = AtomicError("something went wrong")
        assert err.message == "something went wrong"
        assert str(err) == "something went wrong"

    def test_default_empty_context(self) -> None:
        err = AtomicError("error")
        assert err.context == {}

    def test_custom_context(self) -> None:
        ctx = {"module": "sqli", "url": "http://target.com"}
        err = AtomicError("failed", context=ctx)
        assert err.context == ctx
        assert err.context["module"] == "sqli"


class TestNetworkError:
    """Test NetworkError and its subclasses."""

    def test_url_attribute(self) -> None:
        err = NetworkError("connection failed", url="http://example.com")
        assert err.url == "http://example.com"
        assert err.message == "connection failed"

    def test_isinstance_atomic_error(self) -> None:
        err = NetworkError("net error")
        assert isinstance(err, AtomicError)

    def test_connection_timeout_isinstance_chain(self) -> None:
        err = ConnectionTimeoutError("timed out", url="http://slow.com")
        assert isinstance(err, ConnectionTimeoutError)
        assert isinstance(err, NetworkError)
        assert isinstance(err, AtomicError)
        assert err.url == "http://slow.com"

    def test_connection_refused_isinstance_chain(self) -> None:
        err = ConnectionRefusedError("refused", url="http://down.com")
        assert isinstance(err, ConnectionRefusedError)
        assert isinstance(err, NetworkError)
        assert isinstance(err, AtomicError)

    def test_ssl_verification_isinstance_chain(self) -> None:
        err = SSLVerificationError("bad cert", url="https://self-signed.com")
        assert isinstance(err, SSLVerificationError)
        assert isinstance(err, NetworkError)
        assert isinstance(err, AtomicError)

    def test_rate_limit_retry_after(self) -> None:
        err = RateLimitError("too fast", url="http://api.com", retry_after=30.0)
        assert err.retry_after == 30.0
        assert err.url == "http://api.com"
        assert isinstance(err, NetworkError)

    def test_rate_limit_retry_after_none(self) -> None:
        err = RateLimitError("too fast")
        assert err.retry_after is None

    def test_waf_block_waf_name(self) -> None:
        err = WAFBlockError("blocked", url="http://target.com", waf_name="Cloudflare")
        assert err.waf_name == "Cloudflare"
        assert err.url == "http://target.com"
        assert isinstance(err, NetworkError)


class TestScanError:
    """Test ScanError and its subclasses."""

    def test_isinstance_atomic_error(self) -> None:
        err = ScanError("scan failed")
        assert isinstance(err, AtomicError)

    def test_module_load_error_module_name(self) -> None:
        err = ModuleLoadError("cannot load", module_name="sqli")
        assert err.module_name == "sqli"
        assert err.message == "cannot load"
        assert isinstance(err, ScanError)

    def test_module_execution_error_attributes(self) -> None:
        err = ModuleExecutionError(
            "crash", module_name="xss", url="http://target.com/path"
        )
        assert err.module_name == "xss"
        assert err.url == "http://target.com/path"
        assert isinstance(err, ScanError)
        assert isinstance(err, AtomicError)

    def test_payload_error_isinstance_scan_error(self) -> None:
        err = PayloadError("bad payload")
        assert isinstance(err, ScanError)
        assert isinstance(err, AtomicError)


class TestConfigError:
    """Test ConfigError and its subclasses."""

    def test_isinstance_atomic_error(self) -> None:
        err = ConfigError("bad config")
        assert isinstance(err, AtomicError)

    def test_invalid_target_target_attribute(self) -> None:
        err = InvalidTargetError("not reachable", target="http://invalid.local")
        assert err.target == "http://invalid.local"
        assert err.message == "not reachable"
        assert isinstance(err, ConfigError)
        assert isinstance(err, AtomicError)


class TestContextPropagation:
    """Test that context dict propagates through the hierarchy."""

    def test_network_error_with_context(self) -> None:
        ctx = {"retry_count": 3, "last_status": 503}
        err = NetworkError("fail", url="http://x.com", context=ctx)
        assert err.context == ctx

    def test_module_execution_error_with_context(self) -> None:
        ctx = {"traceback": "...", "phase": "test"}
        err = ModuleExecutionError(
            "error", module_name="cmdi", url="http://t.com", context=ctx
        )
        assert err.context["phase"] == "test"
        assert err.module_name == "cmdi"

    def test_invalid_target_with_context(self) -> None:
        ctx = {"reason": "dns_resolution_failed"}
        err = InvalidTargetError("bad", target="http://nx.local", context=ctx)
        assert err.context["reason"] == "dns_resolution_failed"
        assert err.target == "http://nx.local"
