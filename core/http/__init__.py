"""core.http — SafeHTTPClient and policy layers."""
from .safe_client import SafeHTTPClient, URLPolicy, IPPolicy, DNSPolicy, RedirectPolicy

__all__ = ["SafeHTTPClient", "URLPolicy", "IPPolicy", "DNSPolicy", "RedirectPolicy"]
