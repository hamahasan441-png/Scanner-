#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v8.0 - ULTIMATE EDITION
Port Scanner Module

TCP port scanning with service banner grabbing.  Supports individual
ports, comma-separated lists, and ranges (e.g. ``80,443,8080`` or
``1-1024``).  Results are printed in real-time and returned as a list
of dicts for downstream use by the engine.
"""

import socket
import concurrent.futures
from typing import List, Dict, Optional

from config import Colors


# ── Well-known service banners / names ────────────────────────────────────
WELL_KNOWN_PORTS: Dict[int, str] = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 111: 'RPCbind', 135: 'MSRPC',
    139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
    993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle',
    2049: 'NFS', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
    5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt',
    8888: 'HTTP-Alt', 9200: 'Elasticsearch', 27017: 'MongoDB',
}

# Default set when no ports are supplied
TOP_100_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993,
    995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8000, 8080,
    8443, 8888, 9200, 27017,
]


def parse_port_spec(spec: str) -> List[int]:
    """Parse a port specification string into a sorted list of unique ports.

    Accepted formats:
        ``80``            → single port
        ``80,443,8080``   → comma-separated
        ``1-1024``        → range
        ``80,443,8000-9000`` → mixed
    """
    ports: set = set()
    for part in spec.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            try:
                lo, hi = part.split('-', 1)
                lo, hi = int(lo), int(hi)
                if 1 <= lo <= hi <= 65535:
                    ports.update(range(lo, hi + 1))
            except ValueError:
                pass
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                pass
    return sorted(ports)


class PortScanner:
    """TCP port scanner with optional banner grabbing."""

    def __init__(self, engine):
        self.engine = engine
        self.config = engine.config
        self.timeout: float = min(self.config.get('timeout', 3), 5)
        self.threads: int = min(self.config.get('threads', 50), 200)
        self.verbose: bool = self.config.get('verbose', False)

    # ─── public API ──────────────────────────────────────────────────

    def run(self, target: str, port_spec: Optional[str] = None) -> List[Dict]:
        """Scan *target* (hostname or IP) for open ports.

        Parameters
        ----------
        target : str
            Hostname or IP address (``urlparse(url).hostname``).
        port_spec : str | None
            Port specification (see :func:`parse_port_spec`).  When
            ``None``, the top-100 common ports are scanned.

        Returns
        -------
        list[dict]
            Each dict has keys ``port``, ``state``, ``service``, ``banner``.
        """
        ports = parse_port_spec(port_spec) if port_spec else list(TOP_100_PORTS)

        print(f"\n{Colors.BOLD}{'─' * 60}{Colors.RESET}")
        print(f"{Colors.CYAN}  Port Scan: {target} ({len(ports)} ports){Colors.RESET}")
        print(f"{Colors.BOLD}{'─' * 60}{Colors.RESET}\n")

        results: List[Dict] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as pool:
            future_map = {
                pool.submit(self._probe_port, target, port): port
                for port in ports
            }
            for future in concurrent.futures.as_completed(future_map):
                result = future.result()
                if result and result['state'] == 'open':
                    results.append(result)
                    svc = result['service']
                    banner = result['banner']
                    line = f"  {Colors.GREEN}OPEN{Colors.RESET}  {result['port']:>5}/tcp  {svc}"
                    if banner:
                        line += f"  ({banner[:60]})"
                    print(line)

        results.sort(key=lambda r: r['port'])

        print(f"\n{Colors.success(f'Port scan complete: {len(results)} open ports found')}")
        print(f"{Colors.BOLD}{'─' * 60}{Colors.RESET}")

        return results

    # ─── internals ───────────────────────────────────────────────────

    def _probe_port(self, host: str, port: int) -> Dict:
        """Attempt a TCP connection and optional banner grab."""
        result = {
            'port': port,
            'state': 'closed',
            'service': WELL_KNOWN_PORTS.get(port, 'unknown'),
            'banner': '',
        }
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((host, port))
            result['state'] = 'open'
            # Attempt banner grab — first try passive read (many services
            # send a banner immediately), then fall back to sending a probe.
            try:
                sock.settimeout(1.5)
                banner = sock.recv(1024)
                if banner:
                    result['banner'] = banner.decode('utf-8', errors='replace').strip()[:120]
            except (socket.timeout, OSError):
                try:
                    sock.sendall(b'\r\n')
                    banner = sock.recv(1024)
                    if banner:
                        result['banner'] = banner.decode('utf-8', errors='replace').strip()[:120]
                except (socket.timeout, OSError):
                    pass
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        finally:
            sock.close()
        return result
