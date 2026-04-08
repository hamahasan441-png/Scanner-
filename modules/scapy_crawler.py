#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v9.0 - ULTIMATE EDITION
Scapy Network Crawler Module

Low-level network reconnaissance using Scapy for packet-level
scanning.  Provides TCP SYN scanning, UDP probing, OS fingerprinting
via TCP/IP stack analysis, lightweight traceroute, and service
version detection — all complementing the existing socket-based
:class:`modules.port_scanner.PortScanner`.

Usage:
    Runs in §2 Discovery phase after the standard port scan.
    Results feed into the network exploit scanner for CVE matching.

Note:
    Raw-socket operations typically require root / CAP_NET_RAW.
    When privileges are insufficient the module falls back to the
    existing socket-based scanner automatically.
"""

from __future__ import annotations

import socket
import struct
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from config import Colors
from modules.port_scanner import WELL_KNOWN_PORTS, TOP_100_PORTS, parse_port_spec

# ── Scapy availability flag ──────────────────────────────────────────────
_SCAPY_AVAILABLE = False
try:
    from scapy.all import (  # type: ignore[import-untyped]
        IP,
        TCP,
        UDP,
        ICMP,
        sr,
        sr1,
        conf as scapy_conf,
    )

    _SCAPY_AVAILABLE = True
    # Suppress Scapy's verbose output by default
    scapy_conf.verb = 0
except ImportError:
    pass


# ── Top UDP ports & probes ───────────────────────────────────────────────
TOP_UDP_PORTS: Dict[int, str] = {
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    123: "NTP",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    161: "SNMP",
    162: "SNMP-Trap",
    500: "ISAKMP",
    514: "Syslog",
    520: "RIP",
    1900: "SSDP",
    4500: "NAT-T",
    5353: "mDNS",
}

# Minimal protocol probes for common UDP services
_UDP_PROBES: Dict[int, bytes] = {
    53: (  # DNS A query for "version.bind"
        b"\x00\x1e"  # transaction id
        b"\x01\x00"  # standard query
        b"\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x07version\x04bind\x00\x00\x10\x00\x03"
    ),
    123: (  # NTP version request (mode 3 client)
        b"\x1b" + b"\x00" * 47
    ),
    161: (  # SNMP v1 GetRequest for sysDescr (public community)
        b"\x30\x26\x02\x01\x00\x04\x06public"
        b"\xa0\x19\x02\x04\x00\x00\x00\x01"
        b"\x02\x01\x00\x02\x01\x00\x30\x0b"
        b"\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"
    ),
    1900: (  # SSDP M-SEARCH
        b"M-SEARCH * HTTP/1.1\r\n"
        b"HOST: 239.255.255.250:1900\r\n"
        b"MAN: \"ssdp:discover\"\r\n"
        b"MX: 1\r\n"
        b"ST: ssdp:all\r\n\r\n"
    ),
}

# ── OS fingerprint signatures (TTL + window size heuristics) ─────────────
_OS_SIGNATURES: List[Dict] = [
    {"os": "Linux",   "ttl_range": (60, 64),   "window_sizes": {5840, 14600, 29200, 65535}},
    {"os": "Windows", "ttl_range": (125, 128),  "window_sizes": {8192, 16384, 65535}},
    {"os": "macOS",   "ttl_range": (60, 64),    "window_sizes": {65535}},
    {"os": "FreeBSD", "ttl_range": (60, 64),    "window_sizes": {65535}},
    {"os": "Cisco",   "ttl_range": (252, 255),  "window_sizes": {4128}},
    {"os": "Solaris", "ttl_range": (252, 255),  "window_sizes": {8760, 33304}},
]


def is_scapy_available() -> bool:
    """Return ``True`` when the scapy library is importable."""
    return _SCAPY_AVAILABLE


class ScapyCrawler:
    """Packet-level network crawler powered by Scapy.

    Capabilities:
    * **TCP SYN scan** — half-open scan (no full handshake).
    * **UDP probe scan** — protocol-aware probes for common services.
    * **OS fingerprinting** — TTL / window-size heuristic.
    * **Traceroute** — ICMP-based lightweight traceroute.
    * **Service banner detection** — from SYN-ACK options & probe data.
    """

    def __init__(self, engine):
        self.engine = engine
        self.config = engine.config
        self.timeout: float = min(self.config.get("timeout", 3), 5)
        self.verbose: bool = self.config.get("verbose", False)

    # ─── public API ──────────────────────────────────────────────────

    def run(
        self,
        target: str,
        port_spec: Optional[str] = None,
        *,
        syn_scan: bool = True,
        udp_scan: bool = True,
        os_detect: bool = True,
        traceroute: bool = False,
    ) -> Dict:
        """Execute the Scapy network crawl against *target*.

        Parameters
        ----------
        target : str
            Hostname, IP address, or full URL.
        port_spec : str | None
            Port specification (see :func:`parse_port_spec`).
        syn_scan : bool
            Perform TCP SYN half-open scan.
        udp_scan : bool
            Probe common UDP services.
        os_detect : bool
            Attempt passive OS fingerprinting.
        traceroute : bool
            Perform ICMP traceroute.

        Returns
        -------
        dict
            Keys: ``tcp_results``, ``udp_results``, ``os_guess``,
            ``traceroute``, ``host_up``.
        """
        if not _SCAPY_AVAILABLE:
            print(f"{Colors.error('scapy is not installed — skipping Scapy crawler')}")
            return self._empty_result()

        host = self._resolve_host(target)
        if not host:
            print(f"{Colors.error(f'Cannot resolve host: {target}')}")
            return self._empty_result()

        print(f"\n{Colors.BOLD}{'─' * 60}{Colors.RESET}")
        print(f"{Colors.CYAN}  Scapy Network Crawl: {host}{Colors.RESET}")
        print(f"{Colors.BOLD}{'─' * 60}{Colors.RESET}\n")

        result: Dict = self._empty_result()
        result["host_up"] = self._host_alive(host)

        if not result["host_up"]:
            print(f"{Colors.warning(f'Host {host} appears down — skipping scans')}")
            return result

        print(f"{Colors.success(f'Host {host} is up')}")

        # TCP SYN scan
        if syn_scan:
            ports = parse_port_spec(port_spec) if port_spec else list(TOP_100_PORTS)
            result["tcp_results"] = self._syn_scan(host, ports)
            tcp_count = len(result["tcp_results"])
            print(Colors.info(f"SYN scan complete: {tcp_count} open ports"))

        # UDP scan
        if udp_scan:
            result["udp_results"] = self._udp_scan(host)
            open_udp = [r for r in result["udp_results"] if r["state"] == "open"]
            udp_total = len(result["udp_results"])
            print(
                Colors.info(f"UDP scan complete: {len(open_udp)} open / {udp_total} probed")
            )

        # OS fingerprinting (uses data from SYN scan responses)
        if os_detect:
            result["os_guess"] = self._os_fingerprint(host)
            os_guess = result["os_guess"]
            if os_guess:
                print(Colors.info(f"OS guess: {os_guess}"))

        # Traceroute
        if traceroute:
            result["traceroute"] = self._traceroute(host)
            hop_count = len(result["traceroute"])
            if hop_count:
                print(Colors.info(f"Traceroute: {hop_count} hops"))

        print(f"\n{Colors.success('Scapy network crawl complete')}")
        print(f"{Colors.BOLD}{'─' * 60}{Colors.RESET}")

        return result

    # ─── TCP SYN scan ────────────────────────────────────────────────

    def _syn_scan(self, host: str, ports: List[int]) -> List[Dict]:
        """Perform a TCP SYN (half-open) scan on the given ports.

        Sends SYN packets and interprets the response:
        * SYN-ACK → open
        * RST     → closed
        * No reply → filtered
        """
        results: List[Dict] = []
        try:
            # Build SYN packets for all ports at once
            packets = IP(dst=host) / TCP(dport=ports, flags="S")
            answered, _ = sr(packets, timeout=self.timeout, verbose=0)

            for sent, received in answered:
                port = sent[TCP].dport
                flags = received[TCP].flags if TCP in received else 0

                if flags & 0x12 == 0x12:  # SYN-ACK
                    state = "open"
                elif flags & 0x04:  # RST
                    state = "closed"
                else:
                    state = "filtered"

                if state == "open":
                    entry = {
                        "port": port,
                        "state": state,
                        "service": WELL_KNOWN_PORTS.get(port, "unknown"),
                        "banner": "",
                        "protocol": "tcp",
                        "scan_type": "syn",
                        "window_size": (
                            received[TCP].window if TCP in received else 0
                        ),
                        "ttl": received[IP].ttl if IP in received else 0,
                    }
                    results.append(entry)

                    svc = entry["service"]
                    line = f"  {Colors.GREEN}OPEN{Colors.RESET}  {port:>5}/tcp  {svc}"
                    print(line)

        except PermissionError:
            if self.verbose:
                print(
                    f"{Colors.warning('SYN scan requires root — falling back to connect scan')}"
                )
            results = self._connect_fallback(host, ports)
        except Exception as e:
            if self.verbose:
                print(f"{Colors.error(f'SYN scan error: {e}')}")
            results = self._connect_fallback(host, ports)

        results.sort(key=lambda r: r["port"])
        return results

    # ─── UDP scan ────────────────────────────────────────────────────

    def _udp_scan(self, host: str) -> List[Dict]:
        """Probe well-known UDP ports with protocol-specific payloads."""
        results: List[Dict] = []
        for port, service in TOP_UDP_PORTS.items():
            try:
                payload = _UDP_PROBES.get(port, b"\x00" * 8)
                pkt = IP(dst=host) / UDP(dport=port) / payload
                reply = sr1(pkt, timeout=self.timeout, verbose=0)

                if reply is None:
                    state = "open|filtered"
                elif reply.haslayer(UDP):
                    state = "open"
                elif reply.haslayer(ICMP):
                    icmp_type = reply[ICMP].type
                    icmp_code = reply[ICMP].code
                    if icmp_type == 3 and icmp_code == 3:
                        state = "closed"
                    elif icmp_type == 3:
                        state = "filtered"
                    else:
                        state = "open|filtered"
                else:
                    state = "open|filtered"

                banner = ""
                if state == "open" and reply and reply.haslayer(UDP):
                    raw_data = bytes(reply[UDP].payload)
                    if raw_data:
                        banner = raw_data[:80].decode("utf-8", errors="ignore").strip()

                results.append(
                    {
                        "port": port,
                        "state": state,
                        "service": service,
                        "banner": banner,
                        "protocol": "udp",
                        "scan_type": "udp_probe",
                    }
                )

                if state == "open":
                    print(
                        f"  {Colors.GREEN}OPEN{Colors.RESET}  {port:>5}/udp  {service}"
                    )

            except PermissionError:
                if self.verbose:
                    print(
                        f"{Colors.warning(f'UDP scan port {port} requires root — skipped')}"
                    )
            except Exception as e:
                if self.verbose:
                    print(f"{Colors.error(f'UDP scan port {port} error: {e}')}")

        return results

    # ─── OS fingerprinting ───────────────────────────────────────────

    def _os_fingerprint(self, host: str) -> str:
        """Guess the remote OS based on TTL and TCP window size.

        Sends a single SYN to port 80 (or 443) and inspects the
        SYN-ACK response.
        """
        for probe_port in (80, 443, 22):
            try:
                pkt = IP(dst=host) / TCP(dport=probe_port, flags="S")
                reply = sr1(pkt, timeout=self.timeout, verbose=0)
                if reply and reply.haslayer(TCP) and (reply[TCP].flags & 0x12 == 0x12):
                    ttl = reply[IP].ttl
                    win = reply[TCP].window
                    return self._match_os(ttl, win)
            except (PermissionError, Exception):
                continue
        return ""

    @staticmethod
    def _match_os(ttl: int, window_size: int) -> str:
        """Match TTL and window size against known OS signatures."""
        candidates: List[Tuple[str, int]] = []
        for sig in _OS_SIGNATURES:
            score = 0
            lo, hi = sig["ttl_range"]
            if lo <= ttl <= hi:
                score += 2
            if window_size in sig["window_sizes"]:
                score += 1
            if score > 0:
                candidates.append((sig["os"], score))

        if not candidates:
            return f"Unknown (TTL={ttl}, Win={window_size})"

        candidates.sort(key=lambda c: c[1], reverse=True)
        best_os, best_score = candidates[0]
        confidence = "high" if best_score >= 3 else "medium" if best_score == 2 else "low"
        return f"{best_os} (confidence: {confidence}, TTL={ttl}, Win={window_size})"

    # ─── Traceroute ──────────────────────────────────────────────────

    def _traceroute(self, host: str, max_hops: int = 30) -> List[Dict]:
        """ICMP-based traceroute to *host*."""
        hops: List[Dict] = []
        for ttl_val in range(1, max_hops + 1):
            try:
                pkt = IP(dst=host, ttl=ttl_val) / ICMP()
                reply = sr1(pkt, timeout=self.timeout, verbose=0)

                if reply is None:
                    hops.append({"hop": ttl_val, "ip": "*", "rtt_ms": None})
                else:
                    rtt = (reply.time - pkt.sent_time) * 1000 if hasattr(reply, "time") else None
                    hop_ip = reply.src
                    hops.append({"hop": ttl_val, "ip": hop_ip, "rtt_ms": round(rtt, 2) if rtt else None})

                    # Reached the destination
                    if hop_ip == host:
                        break
                    # ICMP echo-reply means we reached the target
                    if reply.haslayer(ICMP) and reply[ICMP].type == 0:
                        break

            except (PermissionError, Exception):
                hops.append({"hop": ttl_val, "ip": "*", "rtt_ms": None})
                break

        return hops

    # ─── Host alive check ────────────────────────────────────────────

    def _host_alive(self, host: str) -> bool:
        """Check if host responds to ICMP echo or TCP SYN on port 80."""
        try:
            pkt = IP(dst=host) / ICMP()
            reply = sr1(pkt, timeout=self.timeout, verbose=0)
            if reply:
                return True
        except (PermissionError, Exception):
            pass

        # Fallback: TCP SYN to port 80
        try:
            pkt = IP(dst=host) / TCP(dport=80, flags="S")
            reply = sr1(pkt, timeout=self.timeout, verbose=0)
            if reply and reply.haslayer(TCP):
                return True
        except (PermissionError, Exception):
            pass

        # Fallback: plain socket connect
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, 80))
            sock.close()
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass

        return False

    # ─── Helpers ─────────────────────────────────────────────────────

    def _connect_fallback(self, host: str, ports: List[int]) -> List[Dict]:
        """Standard connect() scan as fallback when raw sockets are unavailable."""
        results: List[Dict] = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((host, port))
                entry = {
                    "port": port,
                    "state": "open",
                    "service": WELL_KNOWN_PORTS.get(port, "unknown"),
                    "banner": "",
                    "protocol": "tcp",
                    "scan_type": "connect",
                    "window_size": 0,
                    "ttl": 0,
                }
                # Attempt banner grab
                try:
                    sock.settimeout(1.5)
                    banner = sock.recv(1024)
                    if banner:
                        entry["banner"] = banner.decode("utf-8", errors="replace").strip()[:120]
                except (socket.timeout, OSError):
                    pass
                results.append(entry)
                sock.close()

                svc = entry["service"]
                print(
                    f"  {Colors.GREEN}OPEN{Colors.RESET}  {port:>5}/tcp  {svc}"
                )
            except (socket.timeout, ConnectionRefusedError, OSError):
                pass

        return results

    @staticmethod
    def _resolve_host(target: str) -> str:
        """Extract and resolve hostname from a URL or plain host string."""
        if "://" in target:
            parsed = urlparse(target)
            host = parsed.hostname or ""
        else:
            host = target.split(":")[0].strip()

        if not host:
            return ""

        try:
            socket.getaddrinfo(host, None)
            return host
        except socket.gaierror:
            return ""

    @staticmethod
    def _empty_result() -> Dict:
        """Return an empty result dict."""
        return {
            "tcp_results": [],
            "udp_results": [],
            "os_guess": "",
            "traceroute": [],
            "host_up": False,
        }

    # ─── Conversion helpers ──────────────────────────────────────────

    def to_port_scanner_format(self, result: Dict) -> List[Dict]:
        """Convert Scapy results to the format expected by NetworkExploitScanner.

        This allows seamless feeding into the existing exploit-matching
        pipeline.
        """
        converted: List[Dict] = []
        for entry in result.get("tcp_results", []):
            converted.append(
                {
                    "port": entry["port"],
                    "state": entry["state"],
                    "service": entry["service"],
                    "banner": entry["banner"],
                }
            )
        for entry in result.get("udp_results", []):
            if entry["state"] == "open":
                converted.append(
                    {
                        "port": entry["port"],
                        "state": entry["state"],
                        "service": entry["service"],
                        "banner": entry["banner"],
                    }
                )
        return converted


# =====================================================================
# ADVANCED OFFENSIVE RECON SCRIPTS (3 methods)
# =====================================================================


class StealthPortScanner:
    """Script 1 — Stealth TCP scans using FIN, XMAS, and NULL techniques.

    These scan types exploit RFC 793 behavior: a closed port MUST
    respond to a packet that does not contain SYN, RST, or ACK with a
    RST.  An open port silently drops the packet.  This makes the scan
    stealthier than SYN because many IDS/IPS only track SYN-based
    handshakes.

    Techniques:
    * **FIN scan** — only FIN flag set.
    * **XMAS scan** — FIN + PSH + URG (lights up the TCP header like
      a Christmas tree).
    * **NULL scan** — no flags set at all.

    Note: Does not work against Windows hosts (they respond RST
    regardless) — but very effective on UNIX/Linux targets.
    """

    def __init__(self, engine):
        self.engine = engine
        self.timeout: float = min(engine.config.get("timeout", 3), 5)
        self.verbose: bool = engine.config.get("verbose", False)

    def run(self, host: str, ports: Optional[List[int]] = None) -> Dict[str, List[Dict]]:
        """Execute all three stealth scans and return combined results."""
        if not _SCAPY_AVAILABLE:
            print(f"{Colors.error('scapy not installed — stealth scans unavailable')}")
            return {"fin": [], "xmas": [], "null": []}

        ports = ports or list(TOP_100_PORTS)

        print(f"\n{Colors.BOLD}{'─' * 60}{Colors.RESET}")
        print(f"{Colors.CYAN}  Stealth Scan Suite: {host}{Colors.RESET}")
        print(f"{Colors.BOLD}{'─' * 60}{Colors.RESET}\n")

        results: Dict[str, List[Dict]] = {}
        for scan_name, flags in [("fin", "F"), ("xmas", "FPU"), ("null", "")]:
            results[scan_name] = self._stealth_scan(host, ports, flags, scan_name.upper())

        total = sum(len(v) for v in results.values())
        print(f"\n{Colors.success(f'Stealth scans complete — {total} open|filtered ports detected')}")
        print(f"{Colors.BOLD}{'─' * 60}{Colors.RESET}")
        return results

    def _stealth_scan(
        self, host: str, ports: List[int], flags: str, label: str
    ) -> List[Dict]:
        """Generic stealth scan: send packet with *flags* and interpret silence vs RST."""
        open_filtered: List[Dict] = []
        print(f"  {Colors.CYAN}[{label}]{Colors.RESET} Scanning {len(ports)} ports...")

        try:
            packets = IP(dst=host) / TCP(dport=ports, flags=flags)
            answered, unanswered = sr(packets, timeout=self.timeout, verbose=0)

            # Unanswered → open|filtered (no RST came back)
            for sent in unanswered:
                port = sent[TCP].dport
                open_filtered.append({
                    "port": port,
                    "state": "open|filtered",
                    "service": WELL_KNOWN_PORTS.get(port, "unknown"),
                    "scan_type": label.lower(),
                })

            # Answered with RST → closed (skip)
            # Answered with ICMP unreachable → filtered
            for sent, received in answered:
                port = sent[TCP].dport
                if received.haslayer(ICMP):
                    open_filtered.append({
                        "port": port,
                        "state": "filtered",
                        "service": WELL_KNOWN_PORTS.get(port, "unknown"),
                        "scan_type": label.lower(),
                    })

            if open_filtered:
                print(
                    f"    {Colors.GREEN}{len(open_filtered)} open|filtered{Colors.RESET}"
                )

        except PermissionError:
            print(f"    {Colors.warning(f'{label} scan requires root — skipped')}")
        except Exception as e:
            if self.verbose:
                print(f"    {Colors.error(f'{label} scan error: {e}')}")

        return open_filtered


class ARPNetworkDiscovery:
    """Script 2 — ARP-based local network host discovery.

    Sends ARP who-has requests across a subnet to discover live hosts
    on the local network segment.  This is the fastest and most
    reliable way to enumerate hosts on a LAN because ARP operates at
    Layer 2 and cannot be blocked by host firewalls.

    Capabilities:
    * Subnet sweep (e.g. ``192.168.1.0/24``)
    * MAC-address vendor identification (OUI prefix lookup)
    * Gateway detection
    """

    # Minimal OUI → vendor mapping for common infrastructure
    _OUI_TABLE: Dict[str, str] = {
        "00:50:56": "VMware",
        "00:0c:29": "VMware",
        "08:00:27": "VirtualBox",
        "52:54:00": "QEMU/KVM",
        "00:15:5d": "Hyper-V",
        "00:1a:a0": "Dell",
        "b8:27:eb": "Raspberry Pi",
        "dc:a6:32": "Raspberry Pi",
        "f0:de:f1": "Google",
        "00:17:88": "Philips Hue",
        "ac:84:c6": "TP-Link",
        "18:d6:c7": "TP-Link",
        "44:d9:e7": "Ubiquiti",
    }

    def __init__(self, engine):
        self.engine = engine
        self.timeout: float = min(engine.config.get("timeout", 3), 5)
        self.verbose: bool = engine.config.get("verbose", False)

    def discover(self, subnet: str) -> List[Dict]:
        """Send ARP requests to all hosts in *subnet* and collect responses.

        Parameters
        ----------
        subnet : str
            CIDR notation, e.g. ``192.168.1.0/24``.

        Returns
        -------
        list[dict]
            Each dict has keys ``ip``, ``mac``, ``vendor``.
        """
        if not _SCAPY_AVAILABLE:
            print(f"{Colors.error('scapy not installed — ARP discovery unavailable')}")
            return []

        try:
            from scapy.all import ARP, Ether, srp  # type: ignore[import-untyped]
        except ImportError:
            print(f"{Colors.error('scapy ARP layer unavailable')}")
            return []

        print(f"\n{Colors.BOLD}{'─' * 60}{Colors.RESET}")
        print(f"{Colors.CYAN}  ARP Discovery: {subnet}{Colors.RESET}")
        print(f"{Colors.BOLD}{'─' * 60}{Colors.RESET}\n")

        hosts: List[Dict] = []
        try:
            arp_req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
            answered, _ = srp(arp_req, timeout=self.timeout, verbose=0)

            for _, received in answered:
                ip_addr = received.psrc
                mac_addr = received.hwsrc
                vendor = self._lookup_vendor(mac_addr)
                hosts.append({"ip": ip_addr, "mac": mac_addr, "vendor": vendor})
                # Intentional: MAC addresses are the expected output of ARP discovery
                print(
                    f"  {Colors.GREEN}ALIVE{Colors.RESET}  "
                    f"{ip_addr:>15s}  {mac_addr}  {vendor}"  # noqa: S106
                )

        except PermissionError:
            print(f"{Colors.warning('ARP discovery requires root — skipped')}")
        except Exception as e:
            if self.verbose:
                print(f"{Colors.error(f'ARP discovery error: {e}')}")

        print(f"\n{Colors.success(f'ARP discovery complete — {len(hosts)} hosts found')}")
        print(f"{Colors.BOLD}{'─' * 60}{Colors.RESET}")
        return hosts

    @classmethod
    def _lookup_vendor(cls, mac: str) -> str:
        """Match MAC OUI prefix to a vendor name."""
        prefix = mac[:8].lower()
        return cls._OUI_TABLE.get(prefix, "Unknown")


class DNSReconScanner:
    """Script 3 — DNS zone transfer attempt & subdomain brute-force.

    Two-phase DNS reconnaissance:

    1. **Zone transfer (AXFR)** — attempts a full zone transfer
       against every authoritative nameserver for the domain.
       Successful transfers disclose the entire zone file.
    2. **Subdomain brute-force** — resolves a wordlist of common
       subdomains to discover hidden assets.

    Both phases use raw DNS packets via Scapy to maintain maximum
    control over timing and evasion.
    """

    # Common subdomain prefixes for brute-force
    _SUBDOMAIN_WORDLIST: List[str] = [
        "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
        "beta", "portal", "vpn", "remote", "ns1", "ns2", "mx", "smtp",
        "pop", "imap", "webmail", "cloud", "cdn", "static", "assets",
        "media", "blog", "shop", "store", "app", "m", "mobile",
        "intranet", "internal", "git", "gitlab", "jenkins", "ci", "cd",
        "docker", "k8s", "monitor", "grafana", "kibana", "elastic",
        "redis", "db", "database", "backup", "vault", "sso", "auth",
        "login", "secure", "proxy", "gateway", "edge", "lb", "web",
        "www2", "owa", "exchange", "autodiscover", "cpanel", "whm",
        "status", "help", "support", "docs", "wiki", "jira",
    ]

    def __init__(self, engine):
        self.engine = engine
        self.timeout: float = min(engine.config.get("timeout", 3), 5)
        self.verbose: bool = engine.config.get("verbose", False)

    def run(self, domain: str) -> Dict:
        """Run DNS recon against *domain*.

        Returns
        -------
        dict
            Keys: ``zone_transfer`` (list of records), ``subdomains``
            (list of dicts with ``subdomain``, ``ip``).
        """
        print(f"\n{Colors.BOLD}{'─' * 60}{Colors.RESET}")
        print(f"{Colors.CYAN}  DNS Recon: {domain}{Colors.RESET}")
        print(f"{Colors.BOLD}{'─' * 60}{Colors.RESET}\n")

        result: Dict = {"zone_transfer": [], "subdomains": []}

        # Phase 1: Zone transfer
        result["zone_transfer"] = self._attempt_zone_transfer(domain)

        # Phase 2: Subdomain brute-force
        result["subdomains"] = self._brute_subdomains(domain)

        total = len(result["zone_transfer"]) + len(result["subdomains"])
        print(f"\n{Colors.success(f'DNS recon complete — {total} records discovered')}")
        print(f"{Colors.BOLD}{'─' * 60}{Colors.RESET}")
        return result

    def _attempt_zone_transfer(self, domain: str) -> List[Dict]:
        """Attempt AXFR zone transfer against all nameservers."""
        records: List[Dict] = []
        try:
            import dns.resolver
            import dns.zone
            import dns.query
        except ImportError:
            if self.verbose:
                print(f"{Colors.info('dnspython required for zone transfer — skipped')}")
            return records

        # Get NS records
        try:
            ns_answers = dns.resolver.resolve(domain, "NS")
            nameservers = [str(ns).rstrip(".") for ns in ns_answers]
        except Exception:
            nameservers = []

        for ns in nameservers:
            try:
                ns_ip = socket.gethostbyname(ns)
                print(f"  {Colors.info(f'Attempting AXFR against {ns} ({ns_ip})...')}")
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=self.timeout))
                for name, node in zone.nodes.items():
                    rdatasets = node.rdatasets
                    for rdataset in rdatasets:
                        for rdata in rdataset:
                            record = {
                                "name": str(name),
                                "type": dns.rdatatype.to_text(rdataset.rdtype),
                                "value": str(rdata),
                                "nameserver": ns,
                            }
                            records.append(record)
                if records:
                    print(f"    {Colors.GREEN}AXFR SUCCESS — {len(records)} records{Colors.RESET}")
                break  # One successful transfer is enough
            except Exception as e:
                if self.verbose:
                    print(f"    {Colors.warning(f'AXFR failed on {ns}: {e}')}")

        if not records:
            print(f"  {Colors.info('Zone transfer denied (expected for hardened servers)')}")

        return records

    def _brute_subdomains(self, domain: str) -> List[Dict]:
        """Resolve common subdomains via standard DNS A lookups."""
        found: List[Dict] = []
        print(f"  {Colors.info(f'Brute-forcing {len(self._SUBDOMAIN_WORDLIST)} subdomains...')}")

        for prefix in self._SUBDOMAIN_WORDLIST:
            fqdn = f"{prefix}.{domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                found.append({"subdomain": fqdn, "ip": ip})
                print(f"    {Colors.GREEN}FOUND{Colors.RESET}  {fqdn:>40s}  →  {ip}")
            except socket.gaierror:
                pass
            except Exception:
                pass

        print(f"  {Colors.info(f'Subdomain brute-force: {len(found)} found')}")
        return found
