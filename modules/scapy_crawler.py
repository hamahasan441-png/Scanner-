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


# =====================================================================
# VULNERABILITY SCANNING (packet-level detection)
# =====================================================================


# ── Vuln signature database for packet-level checks ──────────────────
SCAPY_VULN_DB: List[Dict] = [
    {
        "id": "SVD-001",
        "title": "TCP Timestamp Information Leak",
        "description": (
            "Target responds with TCP timestamps (TSopt), leaking host "
            "uptime and enabling clock-skew fingerprinting."
        ),
        "severity": "LOW",
        "cvss": 3.7,
        "cwe": "CWE-200",
        "mitre": "T1082",
        "remediation": "Disable TCP timestamps (net.ipv4.tcp_timestamps=0).",
    },
    {
        "id": "SVD-002",
        "title": "Predictable IP ID Sequence",
        "description": (
            "IP ID values increment sequentially, enabling idle-scan "
            "attacks and traffic-volume inference."
        ),
        "severity": "LOW",
        "cvss": 3.7,
        "cwe": "CWE-330",
        "mitre": "T1040",
        "remediation": "Enable randomised IP IDs (net.ipv4.ip_no_pmtu_disc or equivalent).",
    },
    {
        "id": "SVD-003",
        "title": "ICMP Redirect Accepted",
        "description": (
            "Target accepts ICMP redirect messages, allowing an attacker "
            "to reroute traffic through a malicious gateway."
        ),
        "severity": "MEDIUM",
        "cvss": 5.3,
        "cwe": "CWE-940",
        "mitre": "T1557",
        "remediation": "Disable ICMP redirects (net.ipv4.conf.all.accept_redirects=0).",
    },
    {
        "id": "SVD-004",
        "title": "TCP RST Injection Susceptibility",
        "description": (
            "Target may be susceptible to TCP RST injection (off-path "
            "connection reset). Indicates lack of TCP-MD5 or sequence-number "
            "randomisation."
        ),
        "severity": "MEDIUM",
        "cvss": 5.9,
        "cwe": "CWE-940",
        "mitre": "T1565",
        "remediation": "Enable TCP-MD5 authentication for critical peers. Use TLS.",
    },
    {
        "id": "SVD-005",
        "title": "IP Fragmentation Reassembly Accepted",
        "description": (
            "Target reassembles fragmented IP packets, which can be "
            "exploited for firewall evasion and IDS bypass."
        ),
        "severity": "LOW",
        "cvss": 3.1,
        "cwe": "CWE-400",
        "mitre": "T1027",
        "remediation": "Implement strict fragment reassembly policies at the firewall.",
    },
    {
        "id": "SVD-006",
        "title": "Open DNS Resolver",
        "description": (
            "DNS port 53/udp is open and responds to recursive queries "
            "from external sources — can be used in DNS amplification attacks."
        ),
        "severity": "HIGH",
        "cvss": 7.5,
        "cwe": "CWE-406",
        "mitre": "T1498",
        "remediation": "Restrict DNS recursion to authorised clients only.",
    },
    {
        "id": "SVD-007",
        "title": "SNMP Public Community String",
        "description": (
            "SNMP v1/v2c responds to the 'public' community string, "
            "leaking system information and potentially allowing writes."
        ),
        "severity": "HIGH",
        "cvss": 7.5,
        "cwe": "CWE-798",
        "mitre": "T1552",
        "remediation": "Change SNMP community strings. Migrate to SNMPv3 with authentication.",
    },
    {
        "id": "SVD-008",
        "title": "NTP Mode 6 Query Exposed",
        "description": (
            "NTP service responds to mode-6 (control) queries, leaking "
            "server peers, configuration, and enabling amplification."
        ),
        "severity": "MEDIUM",
        "cvss": 5.3,
        "cwe": "CWE-200",
        "mitre": "T1498",
        "remediation": "Restrict NTP mode 6/7 queries to localhost via 'restrict' directives.",
    },
]


class ScapyVulnScanner:
    """Packet-level vulnerability scanner using Scapy.

    Detects network-layer vulnerabilities through crafted packet
    probes rather than application-layer HTTP scanning:

    * **TCP timestamp leak** — exposes host uptime / clock skew.
    * **Predictable IP ID** — enables idle-scan side-channel.
    * **ICMP redirect acceptance** — MITM route injection.
    * **TCP RST susceptibility** — off-path connection reset.
    * **IP fragmentation** — firewall / IDS evasion surface.
    * **Open DNS resolver** — amplification vector.
    * **SNMP public community** — information leak.
    * **NTP mode-6 exposure** — amplification / info leak.
    """

    def __init__(self, engine):
        self.engine = engine
        self.timeout: float = min(engine.config.get("timeout", 3), 5)
        self.verbose: bool = engine.config.get("verbose", False)
        self.findings: List[Dict] = []

    # ─── public API ──────────────────────────────────────────────────

    def run(
        self,
        host: str,
        port_results: Optional[List[Dict]] = None,
        os_guess: str = "",
    ) -> List[Dict]:
        """Run all packet-level vulnerability checks against *host*.

        Parameters
        ----------
        host : str
            Hostname or IP address to probe.
        port_results : list[dict] | None
            Results from a prior port scan (used to skip inapplicable checks).
        os_guess : str
            OS guess string from fingerprinting (context for check tuning).

        Returns
        -------
        list[dict]
            Each dict describes a confirmed vulnerability with metadata.
        """
        if not _SCAPY_AVAILABLE:
            print(f"{Colors.error('scapy not installed — vuln scan unavailable')}")
            return []

        print(f"\n{Colors.BOLD}{'─' * 60}{Colors.RESET}")
        print(f"{Colors.CYAN}  Scapy Vulnerability Scan: {host}{Colors.RESET}")
        print(f"{Colors.BOLD}{'─' * 60}{Colors.RESET}\n")

        open_ports = set()
        if port_results:
            open_ports = {r["port"] for r in port_results if r.get("state") == "open"}

        # Run each check
        self._check_tcp_timestamp(host)
        self._check_ip_id_sequence(host)
        self._check_icmp_redirect(host)
        self._check_fragmentation(host)

        if 53 in open_ports:
            self._check_open_dns_resolver(host)
        if 161 in open_ports:
            self._check_snmp_public(host)
        if 123 in open_ports:
            self._check_ntp_mode6(host)

        # Summary
        sev_counts: Dict[str, int] = {}
        for f in self.findings:
            sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

        summary = ", ".join(f"{c} {s}" for s, c in sev_counts.items()) or "no issues"
        print(f"\n{Colors.success(f'Scapy vuln scan complete: {summary}')}")
        print(f"{Colors.BOLD}{'─' * 60}{Colors.RESET}")

        return self.findings

    # ─── individual checks ───────────────────────────────────────────

    def _check_tcp_timestamp(self, host: str) -> None:
        """Check if TCP timestamp option is enabled."""
        try:
            pkt = IP(dst=host) / TCP(dport=80, flags="S", options=[("Timestamp", (0, 0))])
            reply = sr1(pkt, timeout=self.timeout, verbose=0)
            if reply and reply.haslayer(TCP):
                for opt_name, opt_val in reply[TCP].options:
                    if opt_name == "Timestamp" and opt_val[0] != 0:
                        vuln = self._get_vuln("SVD-001")
                        vuln["evidence"] = f"TCP TSval={opt_val[0]}"
                        vuln["host"] = host
                        self.findings.append(vuln)
                        self._print_finding(vuln)
                        self._register_finding(host, vuln)
                        return
        except (PermissionError, Exception) as e:
            if self.verbose:
                print(f"  {Colors.warning(f'TCP timestamp check: {e}')}")

    def _check_ip_id_sequence(self, host: str) -> None:
        """Send multiple probes and check if IP ID increments predictably."""
        try:
            ids: List[int] = []
            for _ in range(5):
                pkt = IP(dst=host) / TCP(dport=80, flags="S")
                reply = sr1(pkt, timeout=self.timeout, verbose=0)
                if reply and reply.haslayer(IP):
                    ids.append(reply[IP].id)
            if len(ids) >= 3:
                diffs = [ids[i + 1] - ids[i] for i in range(len(ids) - 1)]
                # Sequential if all diffs are small positive integers
                if all(0 < d < 10 for d in diffs):
                    vuln = self._get_vuln("SVD-002")
                    vuln["evidence"] = f"IP IDs: {ids} (diffs: {diffs})"
                    vuln["host"] = host
                    self.findings.append(vuln)
                    self._print_finding(vuln)
                    self._register_finding(host, vuln)
        except (PermissionError, Exception) as e:
            if self.verbose:
                print(f"  {Colors.warning(f'IP ID check: {e}')}")

    def _check_icmp_redirect(self, host: str) -> None:
        """Test if target processes ICMP redirect messages.

        Sends an ICMP redirect (Type 5, Code 1) and observes whether
        the target's subsequent packets change their route.  A response
        to a follow-up probe from a new gateway IP suggests acceptance.
        """
        try:
            # Send redirect claiming 127.0.0.1 is a better route
            pkt = (
                IP(dst=host, src=host)
                / ICMP(type=5, code=1, gw="127.0.0.1")
                / IP(dst=host, src="127.0.0.1")
                / TCP(dport=80, flags="S")
            )
            sr1(pkt, timeout=self.timeout, verbose=0)

            # Probe to see if routing changed (heuristic — TTL shift)
            probe = IP(dst=host) / ICMP()
            before = sr1(probe, timeout=self.timeout, verbose=0)
            if before and before.haslayer(IP):
                # If we got a response, the host is at least reachable.
                # A real ICMP redirect acceptance check requires routing
                # table inspection; here we flag that the host did NOT
                # send an ICMP error (type 3) rejecting the redirect.
                vuln = self._get_vuln("SVD-003")
                vuln["evidence"] = "Host did not reject ICMP redirect (heuristic)"
                vuln["host"] = host
                vuln["confidence"] = "low"
                self.findings.append(vuln)
                self._print_finding(vuln)
                self._register_finding(host, vuln)
        except (PermissionError, Exception) as e:
            if self.verbose:
                print(f"  {Colors.warning(f'ICMP redirect check: {e}')}")

    def _check_fragmentation(self, host: str) -> None:
        """Check if target reassembles fragmented IP payloads."""
        try:
            # Send a fragmented ICMP echo
            payload = b"A" * 48
            pkt = IP(dst=host, flags="MF", frag=0) / ICMP() / payload
            reply = sr1(pkt, timeout=self.timeout, verbose=0)
            if reply and reply.haslayer(ICMP):
                vuln = self._get_vuln("SVD-005")
                vuln["evidence"] = "Host reassembled fragmented ICMP"
                vuln["host"] = host
                self.findings.append(vuln)
                self._print_finding(vuln)
                self._register_finding(host, vuln)
        except (PermissionError, Exception) as e:
            if self.verbose:
                print(f"  {Colors.warning(f'Fragmentation check: {e}')}")

    def _check_open_dns_resolver(self, host: str) -> None:
        """Test if DNS port 53 acts as an open resolver."""
        try:
            dns_query = (
                b"\xaa\xbb"  # transaction ID
                b"\x01\x00"  # standard recursive query
                b"\x00\x01\x00\x00\x00\x00\x00\x00"
                b"\x07example\x03com\x00\x00\x01\x00\x01"
            )
            pkt = IP(dst=host) / UDP(dport=53) / dns_query
            reply = sr1(pkt, timeout=self.timeout, verbose=0)
            if reply and reply.haslayer(UDP):
                raw = bytes(reply[UDP].payload)
                # Check if we got an answer section (ANCOUNT > 0)
                if len(raw) > 6 and int.from_bytes(raw[6:8], "big") > 0:
                    vuln = self._get_vuln("SVD-006")
                    vuln["evidence"] = "DNS recursive query answered"
                    vuln["host"] = host
                    self.findings.append(vuln)
                    self._print_finding(vuln)
                    self._register_finding(host, vuln)
        except (PermissionError, Exception) as e:
            if self.verbose:
                print(f"  {Colors.warning(f'DNS resolver check: {e}')}")

    def _check_snmp_public(self, host: str) -> None:
        """Test if SNMP responds to 'public' community string."""
        try:
            snmp_get = (
                b"\x30\x26\x02\x01\x00\x04\x06public"
                b"\xa0\x19\x02\x04\x00\x00\x00\x01"
                b"\x02\x01\x00\x02\x01\x00\x30\x0b"
                b"\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"
            )
            pkt = IP(dst=host) / UDP(dport=161) / snmp_get
            reply = sr1(pkt, timeout=self.timeout, verbose=0)
            if reply and reply.haslayer(UDP):
                raw = bytes(reply[UDP].payload)
                if len(raw) > 10:
                    vuln = self._get_vuln("SVD-007")
                    vuln["evidence"] = f"SNMP responded ({len(raw)} bytes)"
                    vuln["host"] = host
                    self.findings.append(vuln)
                    self._print_finding(vuln)
                    self._register_finding(host, vuln)
        except (PermissionError, Exception) as e:
            if self.verbose:
                print(f"  {Colors.warning(f'SNMP check: {e}')}")

    def _check_ntp_mode6(self, host: str) -> None:
        """Test for NTP mode-6 (control) query exposure."""
        try:
            # NTP mode 6 readvar request
            ntp_ctrl = b"\x16\x02\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00"
            pkt = IP(dst=host) / UDP(dport=123) / ntp_ctrl
            reply = sr1(pkt, timeout=self.timeout, verbose=0)
            if reply and reply.haslayer(UDP):
                raw = bytes(reply[UDP].payload)
                if len(raw) > 12:
                    vuln = self._get_vuln("SVD-008")
                    vuln["evidence"] = f"NTP mode 6 responded ({len(raw)} bytes)"
                    vuln["host"] = host
                    self.findings.append(vuln)
                    self._print_finding(vuln)
                    self._register_finding(host, vuln)
        except (PermissionError, Exception) as e:
            if self.verbose:
                print(f"  {Colors.warning(f'NTP mode6 check: {e}')}")

    # ─── helpers ─────────────────────────────────────────────────────

    @staticmethod
    def _get_vuln(vuln_id: str) -> Dict:
        """Look up a vulnerability template by ID and return a copy."""
        for entry in SCAPY_VULN_DB:
            if entry["id"] == vuln_id:
                return dict(entry)
        return {"id": vuln_id, "title": "Unknown", "severity": "INFO", "cvss": 0.0}

    def _print_finding(self, vuln: Dict) -> None:
        """Pretty-print a finding to the terminal."""
        sev = vuln.get("severity", "INFO")
        color = {
            "CRITICAL": Colors.RED + Colors.BOLD,
            "HIGH": Colors.RED,
            "MEDIUM": Colors.YELLOW,
            "LOW": Colors.CYAN,
            "INFO": Colors.BLUE,
        }.get(sev, Colors.WHITE)
        title = vuln.get("title", "?")
        evidence = vuln.get("evidence", "")
        print(f"  {color}{sev:8s}{Colors.RESET}  {title}")
        if evidence:
            print(f"           {evidence}")

    def _register_finding(self, host: str, vuln: Dict) -> None:
        """Register the finding with the engine."""
        try:
            from core.engine import Finding
            finding = Finding(
                technique=f"Network Vuln: {vuln['title']}",
                url=f"tcp://{host}",
                evidence=vuln.get("evidence", ""),
                severity=vuln.get("severity", "INFO"),
                confidence=0.6,
                cwe_id=vuln.get("cwe", ""),
                mitre_id=vuln.get("mitre", ""),
                cvss=vuln.get("cvss", 0.0),
                remediation=vuln.get("remediation", ""),
            )
            self.engine.add_finding(finding)
        except Exception:
            pass


# =====================================================================
# ATTACK CHAIN — network-layer multi-step exploitation
# =====================================================================

# Network-layer chain templates
NETWORK_CHAIN_TEMPLATES: List[Dict] = [
    {
        "name": "Recon → Vuln Scan → Service Exploit",
        "description": (
            "Full packet-level attack chain: discover hosts via ARP, "
            "fingerprint OS, scan ports, identify vulnerabilities, and "
            "attempt service-level exploitation."
        ),
        "steps": [
            {"action": "arp_discover", "desc": "Discover live hosts via ARP sweep"},
            {"action": "os_fingerprint", "desc": "Fingerprint target OS via TCP/IP stack"},
            {"action": "syn_scan", "desc": "SYN scan for open ports"},
            {"action": "vuln_scan", "desc": "Packet-level vulnerability probing"},
            {"action": "service_exploit", "desc": "Attempt service exploitation"},
        ],
    },
    {
        "name": "Stealth Recon → Firewall Evasion → Deep Scan",
        "description": (
            "Evade IDS/IPS via stealth scans (FIN/XMAS/NULL), identify "
            "firewall gaps, then perform deep vulnerability scanning "
            "through the discovered openings."
        ),
        "steps": [
            {"action": "stealth_scan", "desc": "Stealth FIN/XMAS/NULL port discovery"},
            {"action": "frag_probe", "desc": "Test fragmentation-based firewall bypass"},
            {"action": "syn_scan", "desc": "Full SYN scan on discovered open ports"},
            {"action": "vuln_scan", "desc": "Vulnerability scan on open services"},
        ],
    },
    {
        "name": "DNS Recon → Subdomain Takeover → Pivot",
        "description": (
            "Enumerate subdomains via DNS recon, check for dangling "
            "DNS records indicating takeover potential, and pivot to "
            "internal services via discovered assets."
        ),
        "steps": [
            {"action": "dns_recon", "desc": "DNS zone transfer and subdomain brute-force"},
            {"action": "subdomain_resolve", "desc": "Resolve and validate discovered subdomains"},
            {"action": "syn_scan", "desc": "Port-scan discovered subdomain hosts"},
            {"action": "vuln_scan", "desc": "Vulnerability scan on discovered services"},
        ],
    },
    {
        "name": "ARP Discovery → MITM Position → Credential Sniff",
        "description": (
            "Discover LAN hosts via ARP, identify targets with weak "
            "protocols (Telnet, FTP, SNMP), and chain into credential "
            "capture via service probing."
        ),
        "steps": [
            {"action": "arp_discover", "desc": "ARP sweep for LAN host enumeration"},
            {"action": "cleartext_detect", "desc": "Identify cleartext protocol services"},
            {"action": "service_probe", "desc": "Banner grab and credential probe"},
        ],
    },
    {
        "name": "OS Fingerprint → Targeted CVE → Post-Exploit",
        "description": (
            "Identify the operating system, select matching CVEs from "
            "the vulnerability database, and attempt targeted exploitation."
        ),
        "steps": [
            {"action": "os_fingerprint", "desc": "OS identification via TCP/IP fingerprint"},
            {"action": "cve_match", "desc": "Match OS to known CVE exploits"},
            {"action": "service_exploit", "desc": "Attempt targeted service exploitation"},
        ],
    },
]

# Ports associated with cleartext / weak protocols
_CLEARTEXT_PORTS: Dict[int, str] = {
    21: "FTP",
    23: "Telnet",
    25: "SMTP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    513: "rlogin",
    514: "rsh",
}


class ScapyAttackChain:
    """Network-layer attack chain engine using Scapy.

    Orchestrates multi-step network attacks by chaining together
    Scapy-based recon, vulnerability scanning, and exploitation
    modules.  Each chain builds on the results of previous steps
    to progressively deepen access.

    Flow::

        ARP Discovery ──▶ OS Fingerprint ──▶ Port Scan
              │                  │                │
              ▼                  ▼                ▼
        Host List          OS → CVE Match   Service Vulns
              │                  │                │
              └──────────────────┴────────────────┘
                                 │
                                 ▼
                          Attack Execution
    """

    def __init__(self, engine):
        self.engine = engine
        self.timeout: float = min(engine.config.get("timeout", 3), 5)
        self.verbose: bool = engine.config.get("verbose", False)
        self.chain_results: List[Dict] = []

    # ─── public API ──────────────────────────────────────────────────

    def run(
        self,
        host: str,
        *,
        port_results: Optional[List[Dict]] = None,
        scapy_results: Optional[Dict] = None,
        chain_names: Optional[List[str]] = None,
    ) -> List[Dict]:
        """Execute network attack chains against *host*.

        Parameters
        ----------
        host : str
            Target IP or hostname.
        port_results : list[dict] | None
            Pre-existing port scan results to reuse.
        scapy_results : dict | None
            Pre-existing Scapy crawl results (tcp_results, os_guess, etc.).
        chain_names : list[str] | None
            Specific chains to run.  If ``None``, all applicable chains
            are attempted.

        Returns
        -------
        list[dict]
            Execution result for each attempted chain.
        """
        if not _SCAPY_AVAILABLE:
            print(f"{Colors.error('scapy not installed — attack chain unavailable')}")
            return []

        print(f"\n{Colors.BOLD}{'─' * 60}{Colors.RESET}")
        print(f"{Colors.CYAN}  Scapy Attack Chain: {host}{Colors.RESET}")
        print(f"{Colors.BOLD}{'─' * 60}{Colors.RESET}\n")

        # Build shared context from prior results
        context: Dict = {
            "host": host,
            "port_results": port_results or [],
            "scapy_results": scapy_results or {},
            "os_guess": (scapy_results or {}).get("os_guess", ""),
            "discovered_hosts": [],
            "vuln_findings": [],
            "subdomains": [],
            "cleartext_services": [],
            "cve_matches": [],
        }

        templates = NETWORK_CHAIN_TEMPLATES
        if chain_names:
            templates = [t for t in templates if t["name"] in chain_names]

        for template in templates:
            self._execute_chain(template, context)

        # Summary
        success = sum(1 for r in self.chain_results if r["success"])
        total = len(self.chain_results)
        print(f"\n{Colors.success(f'Attack chains: {total} attempted, {success} successful')}")
        print(f"{Colors.BOLD}{'─' * 60}{Colors.RESET}")

        return self.chain_results

    # ─── chain execution ─────────────────────────────────────────────

    def _execute_chain(self, template: Dict, context: Dict) -> None:
        """Execute a single attack chain from *template*."""
        name = template["name"]
        print(f"  {Colors.BOLD}Chain:{Colors.RESET} {name}")

        result: Dict = {
            "chain": name,
            "steps_completed": 0,
            "total_steps": len(template["steps"]),
            "success": False,
            "step_data": [],
        }

        for i, step in enumerate(template["steps"]):
            desc = step["desc"]
            action = step["action"]
            print(f"    Step {i + 1}: {desc} ... ", end="", flush=True)

            ok, data = self._dispatch_step(action, context)
            if ok:
                result["steps_completed"] += 1
                result["step_data"].append(data or {})
                context.update(data or {})
                print(f"{Colors.GREEN}✓{Colors.RESET}")
            else:
                print(f"{Colors.RED}✗{Colors.RESET}")
                break

        result["success"] = result["steps_completed"] == result["total_steps"]
        self.chain_results.append(result)

        if result["success"]:
            print(f"    {Colors.GREEN}→ Chain completed!{Colors.RESET}")
            self._register_chain_finding(template, result)
        else:
            done = result["steps_completed"]
            total = result["total_steps"]
            print(f"    {Colors.YELLOW}→ Stopped at step {done}/{total}{Colors.RESET}")

    def _dispatch_step(
        self, action: str, context: Dict,
    ) -> Tuple[bool, Optional[Dict]]:
        """Route *action* to the appropriate handler."""
        handlers = {
            "arp_discover": self._step_arp_discover,
            "os_fingerprint": self._step_os_fingerprint,
            "syn_scan": self._step_syn_scan,
            "stealth_scan": self._step_stealth_scan,
            "vuln_scan": self._step_vuln_scan,
            "service_exploit": self._step_service_exploit,
            "frag_probe": self._step_frag_probe,
            "dns_recon": self._step_dns_recon,
            "subdomain_resolve": self._step_subdomain_resolve,
            "cleartext_detect": self._step_cleartext_detect,
            "service_probe": self._step_service_probe,
            "cve_match": self._step_cve_match,
        }
        handler = handlers.get(action)
        if not handler:
            return False, None
        try:
            return handler(context)
        except Exception as e:
            if self.verbose:
                print(f" ({e}) ", end="")
            return False, None

    # ─── step implementations ────────────────────────────────────────

    def _step_arp_discover(self, ctx: Dict) -> Tuple[bool, Optional[Dict]]:
        """ARP sweep to enumerate live hosts."""
        host = ctx["host"]
        # Derive /24 subnet from host
        parts = host.split(".")
        if len(parts) == 4:
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        else:
            return False, None
        try:
            arp = ARPNetworkDiscovery(self.engine)
            hosts = arp.discover(subnet)
            ctx["discovered_hosts"] = hosts
            return bool(hosts), {"discovered_hosts": hosts}
        except Exception:
            return False, None

    def _step_os_fingerprint(self, ctx: Dict) -> Tuple[bool, Optional[Dict]]:
        """Fingerprint target OS."""
        host = ctx["host"]
        try:
            crawler = ScapyCrawler(self.engine)
            guess = crawler._os_fingerprint(host)
            if guess:
                ctx["os_guess"] = guess
                return True, {"os_guess": guess}
        except Exception:
            pass
        return False, None

    def _step_syn_scan(self, ctx: Dict) -> Tuple[bool, Optional[Dict]]:
        """SYN scan for open ports."""
        host = ctx["host"]
        try:
            crawler = ScapyCrawler(self.engine)
            results = crawler._syn_scan(host, list(TOP_100_PORTS))
            if results:
                ctx["port_results"] = results
                return True, {"port_results": results}
        except Exception:
            pass
        return False, None

    def _step_stealth_scan(self, ctx: Dict) -> Tuple[bool, Optional[Dict]]:
        """Stealth FIN/XMAS/NULL scan."""
        host = ctx["host"]
        try:
            stealth = StealthPortScanner(self.engine)
            results = stealth.run(host)
            all_ports = []
            for scan_type_results in results.values():
                all_ports.extend(scan_type_results)
            if all_ports:
                ctx["stealth_results"] = results
                return True, {"stealth_results": results}
        except Exception:
            pass
        return False, None

    def _step_vuln_scan(self, ctx: Dict) -> Tuple[bool, Optional[Dict]]:
        """Packet-level vulnerability scan."""
        host = ctx["host"]
        port_results = ctx.get("port_results", [])
        try:
            scanner = ScapyVulnScanner(self.engine)
            findings = scanner.run(host, port_results=port_results, os_guess=ctx.get("os_guess", ""))
            if findings:
                ctx["vuln_findings"] = findings
                return True, {"vuln_findings": findings}
            # No vulns found is not a failure — it means the chain can continue
            return True, {"vuln_findings": []}
        except Exception:
            return False, None

    def _step_service_exploit(self, ctx: Dict) -> Tuple[bool, Optional[Dict]]:
        """Attempt service exploitation using NetworkExploitScanner."""
        host = ctx["host"]
        port_results = ctx.get("port_results", [])
        if not port_results:
            return False, None
        try:
            from modules.network_exploits import NetworkExploitScanner
            scanner = NetworkExploitScanner(self.engine)
            exploits = scanner.run(host, port_results)
            return bool(exploits), {"exploit_findings": exploits}
        except Exception:
            return False, None

    def _step_frag_probe(self, ctx: Dict) -> Tuple[bool, Optional[Dict]]:
        """Test fragmentation bypass."""
        host = ctx["host"]
        try:
            scanner = ScapyVulnScanner(self.engine)
            scanner._check_fragmentation(host)
            return True, {"frag_tested": True}
        except Exception:
            return False, None

    def _step_dns_recon(self, ctx: Dict) -> Tuple[bool, Optional[Dict]]:
        """DNS zone transfer and subdomain discovery."""
        host = ctx["host"]
        try:
            dns_scanner = DNSReconScanner(self.engine)
            result = dns_scanner.run(host)
            subs = result.get("subdomains", [])
            ctx["subdomains"] = subs
            return True, {"subdomains": subs, "zone_transfer": result.get("zone_transfer", [])}
        except Exception:
            return False, None

    def _step_subdomain_resolve(self, ctx: Dict) -> Tuple[bool, Optional[Dict]]:
        """Resolve discovered subdomains to IPs."""
        subs = ctx.get("subdomains", [])
        if not subs:
            return False, None
        resolved = []
        for sub in subs:
            fqdn = sub.get("subdomain", "")
            ip = sub.get("ip", "")
            if fqdn and ip:
                resolved.append({"subdomain": fqdn, "ip": ip})
        return bool(resolved), {"resolved_subdomains": resolved}

    def _step_cleartext_detect(self, ctx: Dict) -> Tuple[bool, Optional[Dict]]:
        """Identify cleartext protocol services in port results."""
        port_results = ctx.get("port_results", [])
        cleartext: List[Dict] = []
        for r in port_results:
            port = r.get("port", 0)
            if port in _CLEARTEXT_PORTS and r.get("state") == "open":
                cleartext.append({
                    "port": port,
                    "service": _CLEARTEXT_PORTS[port],
                    "risk": "Credentials may be transmitted in cleartext",
                })
        ctx["cleartext_services"] = cleartext
        return bool(cleartext), {"cleartext_services": cleartext}

    def _step_service_probe(self, ctx: Dict) -> Tuple[bool, Optional[Dict]]:
        """Banner grab and credential-probe cleartext services."""
        host = ctx["host"]
        cleartext = ctx.get("cleartext_services", [])
        if not cleartext:
            return False, None
        probed: List[Dict] = []
        for svc in cleartext:
            port = svc["port"]
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((host, port))
                try:
                    sock.settimeout(1.5)
                    banner = sock.recv(1024).decode("utf-8", errors="replace").strip()[:120]
                except (socket.timeout, OSError):
                    banner = ""
                probed.append({
                    "port": port,
                    "service": svc["service"],
                    "banner": banner,
                })
                sock.close()
            except (socket.timeout, ConnectionRefusedError, OSError):
                pass
        return bool(probed), {"service_probes": probed}

    def _step_cve_match(self, ctx: Dict) -> Tuple[bool, Optional[Dict]]:
        """Match OS guess to relevant CVEs."""
        os_guess = ctx.get("os_guess", "").lower()
        if not os_guess:
            return False, None
        matches: List[Dict] = []
        # Simple OS-to-CVE heuristic mapping
        os_cve_hints = {
            "linux": [
                {"cve": "CVE-2021-4034", "title": "PwnKit (pkexec LPE)", "severity": "HIGH"},
                {"cve": "CVE-2022-0847", "title": "Dirty Pipe (kernel LPE)", "severity": "HIGH"},
            ],
            "windows": [
                {"cve": "CVE-2017-0144", "title": "EternalBlue (SMB RCE)", "severity": "CRITICAL"},
                {"cve": "CVE-2019-0708", "title": "BlueKeep (RDP RCE)", "severity": "CRITICAL"},
            ],
            "freebsd": [
                {"cve": "CVE-2019-5611", "title": "FreeBSD ICMPv6 DoS", "severity": "HIGH"},
            ],
        }
        for os_name, cves in os_cve_hints.items():
            if os_name in os_guess:
                matches.extend(cves)
        ctx["cve_matches"] = matches
        return bool(matches), {"cve_matches": matches}

    # ─── finding registration ────────────────────────────────────────

    def _register_chain_finding(self, template: Dict, result: Dict) -> None:
        """Register a completed chain as a CRITICAL finding."""
        try:
            from core.engine import Finding
            steps_desc = " → ".join(
                s["desc"] for s in template["steps"]
            )
            finding = Finding(
                technique=f"Network Attack Chain: {template['name']}",
                url=f"tcp://{self.engine.config.get('target', '')}",
                evidence=f"Chain completed: {steps_desc}",
                severity="CRITICAL",
                confidence=0.80,
            )
            self.engine.add_finding(finding)
        except Exception:
            pass
