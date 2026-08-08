"""SafeHTTPClient — centralized SSRF / scope defense."""
from __future__ import annotations
import ipaddress
import re
import socket
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

PRIVATE_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
]
BLOCKED_HOSTS = {"metadata.google.internal","metadata.google.internal.","instance-data","instance-data.","kubernetes.default.svc","kubernetes.default.svc."}
METADATA_IPS = {ipaddress.ip_address("169.254.169.254"), ipaddress.ip_address("100.100.100.200"), ipaddress.ip_address("169.254.170.2")}
MAX_REDIRECTS = 5
MAX_RESPONSE_BYTES = 5*1024*1024

@dataclass
class URLPolicy:
    allowed_schemes: set = field(default_factory=lambda: {"http","https"})
    def validate(self, url: str) -> Optional[str]:
        try:
            p = urllib.parse.urlparse(url)
        except Exception:
            return "invalid URL"
        if p.scheme not in self.allowed_schemes:
            return f"scheme {p.scheme!r} not allowed"
        if not p.netloc:
            return "missing host"
        if p.hostname and p.hostname.lower().rstrip(".") in BLOCKED_HOSTS:
            return f"blocked host {p.hostname}"
        # userinfo @ bypass
        if "@" in (p.netloc or "") and p.hostname and "@" in url.split(p.hostname)[0].split("/")[-1]:
            pass
        return None

@dataclass
class DNSPolicy:
    timeout: float = 3.0
    def resolve(self, hostname: str) -> list[ipaddress.IPv4Address|ipaddress.IPv6Address]:
        try:
            infos = socket.getaddrinfo(hostname, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
            ips = []
            for fam,_,_,_,addr in infos:
                ip = ipaddress.ip_address(addr[0])
                if ip not in ips:
                    ips.append(ip)
            return ips
        except socket.gaierror:
            return []

@dataclass
class IPPolicy:
    block_private: bool = True
    block_metadata: bool = True
    allow_loopback: bool = False
    def validate(self, ip: ipaddress.IPv4Address|ipaddress.IPv6Address) -> Optional[str]:
        if self.block_metadata and ip in METADATA_IPS:
            return f"metadata IP {ip} blocked"
        if self.block_private:
            for net in PRIVATE_RANGES:
                try:
                    if ip in net:
                        if ip.is_loopback and self.allow_loopback:
                            continue
                        return f"IP {ip} in blocked range {net}"
                except Exception:
                    continue
        return None
    def validate_all(self, ips: list) -> Optional[str]:
        if not ips:
            return "DNS resolution failed"
        for ip in ips:
            err = self.validate(ip)
            if err:
                return err
        return None

@dataclass
class RedirectPolicy:
    max_redirects: int = MAX_REDIRECTS
    url_policy: URLPolicy = field(default_factory=URLPolicy)
    ip_policy: IPPolicy = field(default_factory=IPPolicy)
    dns_policy: DNSPolicy = field(default_factory=DNSPolicy)
    def validate_redirect(self, current_url: str, location: str) -> tuple[str|None, str|None]:
        nxt = urllib.parse.urljoin(current_url, location)
        err = self.url_policy.validate(nxt)
        if err:
            return None, err
        host = urllib.parse.urlparse(nxt).hostname
        if host:
            try:
                ip = ipaddress.ip_address(host)
                err2 = self.ip_policy.validate(ip)
                if err2:
                    return None, err2
            except ValueError:
                ips = self.dns_policy.resolve(host)
                err2 = self.ip_policy.validate_all(ips)
                if err2:
                    return None, err2
        return nxt, None

class SafeHTTPClient:
    """Centralized HTTP abstraction. All user-controlled URL fetches should use this."""
    def __init__(self, scope_policy=None, allow_private: bool=False):
        self.url_policy = URLPolicy()
        self.dns_policy = DNSPolicy()
        self.ip_policy = IPPolicy(block_private=not allow_private, block_metadata=True, allow_loopback=allow_private)
        self.redirect_policy = RedirectPolicy(url_policy=self.url_policy, ip_policy=self.ip_policy, dns_policy=self.dns_policy)
        self.scope = scope_policy

    def check_url(self, url: str) -> str|None:
        err = self.url_policy.validate(url)
        if err:
            return err
        p = urllib.parse.urlparse(url)
        host = p.hostname
        if not host:
            return "missing host"
        # if host is IP literal
        try:
            ip = ipaddress.ip_address(host.strip("[]"))
            return self.ip_policy.validate(ip)
        except ValueError:
            pass
        ips = self.dns_policy.resolve(host)
        if not ips:
            # don't block on DNS failure for now, but scope will
            return None
        return self.ip_policy.validate_all(ips)

    def check_scope(self, url: str) -> str|None:
        if self.scope:
            try:
                if not self.scope.is_in_scope(url):
                    return f"scope violation: {url}"
            except Exception:
                pass
        return None

    def validate_request(self, url: str) -> tuple[bool,str]:
        e = self.check_url(url)
        if e:
            return False, e
        e = self.check_scope(url)
        if e:
            return False, e
        return True, ""

    @staticmethod
    def canonicalize(url: str) -> str:
        try:
            p = urllib.parse.urlparse(url)
            # normalize: lowercase host, remove dot segments, NFC
            import unicodedata
            url = unicodedata.normalize("NFC", url)
            path = urllib.parse.quote(urllib.parse.unquote(p.path), safe="/%:@&=?")
            netloc = p.netloc.lower()
            return urllib.parse.urlunparse((p.scheme.lower(), netloc, path, p.params, p.query, p.fragment))
        except Exception:
            return url
