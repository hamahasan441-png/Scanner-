"""ATOMIC FRAMEWORK - Custom Exception Hierarchy

Provides structured error types so callers can handle specific failure
modes (network, scan, config) without catching bare Exception.
"""
from __future__ import annotations

from typing import Any, Optional


class AtomicError(Exception):
    """Base exception for all ATOMIC Framework errors."""

    def __init__(self, message: str = "", context: Optional[dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.message = message
        self.context: dict[str, Any] = context or {}


# --- Network Errors ---


class NetworkError(AtomicError):
    """Base class for network-related errors."""

    def __init__(self, message: str = "", url: str = "", **kwargs: Any) -> None:
        super().__init__(message, **kwargs)
        self.url = url


class ConnectionTimeoutError(NetworkError):
    """Request timed out."""

    pass


class ConnectionRefusedError(NetworkError):
    """Target refused connection."""

    pass


class SSLVerificationError(NetworkError):
    """SSL/TLS verification failed."""

    pass


class RateLimitError(NetworkError):
    """Target is rate limiting requests (429)."""

    def __init__(
        self,
        message: str = "",
        url: str = "",
        retry_after: Optional[float] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, url=url, **kwargs)
        self.retry_after = retry_after


class WAFBlockError(NetworkError):
    """Request was blocked by WAF."""

    def __init__(
        self,
        message: str = "",
        url: str = "",
        waf_name: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(message, url=url, **kwargs)
        self.waf_name = waf_name


# --- Scan Errors ---


class ScanError(AtomicError):
    """Base class for scan execution errors."""

    pass


class ModuleLoadError(ScanError):
    """Failed to load/initialize a scan module."""

    def __init__(self, message: str = "", module_name: str = "", **kwargs: Any) -> None:
        super().__init__(message, **kwargs)
        self.module_name = module_name


class ModuleExecutionError(ScanError):
    """Module raised an unhandled exception during test()."""

    def __init__(
        self,
        message: str = "",
        module_name: str = "",
        url: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.module_name = module_name
        self.url = url


class PayloadError(ScanError):
    """Invalid or missing payload configuration."""

    pass


# --- Configuration Errors ---


class ConfigError(AtomicError):
    """Invalid framework configuration."""

    pass


class InvalidTargetError(ConfigError):
    """Target URL is invalid or unreachable."""

    def __init__(self, message: str = "", target: str = "", **kwargs: Any) -> None:
        super().__init__(message, **kwargs)
        self.target = target
