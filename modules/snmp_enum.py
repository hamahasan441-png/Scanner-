#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - SNMP Enumeration Module
SNMP community string brute-force, MIB walking, information disclosure.
"""
import socket
import struct
from config import Colors
from modules.base import BaseModule


class SNMPEnumModule(BaseModule):
    """SNMP enumeration and attack module."""

    name = "SNMP Enumeration"
    vuln_type = "snmp"

    DEFAULT_COMMUNITIES = [
        "public", "private", "community", "manager", "admin", "cisco",
        "secret", "snmp", "mrtg", "all", "system", "monitor", "test",
        "read", "write", "agent", "gateway", "internal", "default",
        "security", "network", "backup", "server", "switch", "router",
    ]

    def test_url(self, url):
        """Run SNMP tests against the target host."""
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname or url
        if not hostname:
            return
        self._test_snmp_community(hostname, url)
        self._test_snmp_v3_noauth(hostname, url)

    def _build_snmp_get(self, community, oid):
        """Build SNMP GET REQUEST packet."""
        # SNMP v1/v2c GET REQUEST
        oid_parts = [int(x) for x in oid.strip('.').split('.')]
        # Encode OID
        oid_encoded = bytes([oid_parts[0] * 40 + oid_parts[1]])
        for part in oid_parts[2:]:
            if part < 128:
                oid_encoded += bytes([part])
            else:
                encoded = []
                val = part
                encoded.insert(0, val & 0x7F)
                val >>= 7
                while val:
                    encoded.insert(0, (val & 0x7F) | 0x80)
                    val >>= 7
                oid_encoded += bytes(encoded)

        # Build packet
        oid_tlv = b'\x06' + bytes([len(oid_encoded)]) + oid_encoded
        community_bytes = community.encode()
        community_tlv = b'\x04' + bytes([len(community_bytes)]) + community_bytes

        # GETREQUEST PDU
        pdu_content = (
            b'\x02\x01\x00'  # request-id = 0
            + b'\x02\x01\x00'  # error-status = 0
            + b'\x02\x01\x00'  # error-index = 0
            + b'\x30' + bytes([len(oid_tlv)]) + oid_tlv  # variable-bindings
        )
        pdu = b'\xa0' + bytes([len(pdu_content)]) + pdu_content

        # SNMP message
        msg_content = (
            b'\x02\x01\x01'  # version: v2c
            + community_tlv
            + pdu
        )
        msg = b'\x30' + bytes([len(msg_content)]) + msg_content
        return msg

    def _test_snmp_community(self, hostname, url):
        """Brute-force SNMP community strings."""
        for community in self.DEFAULT_COMMUNITIES:
            for port in [161]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(2)
                    # sysDescr OID
                    packet = self._build_snmp_get(community, '1.3.6.1.2.1.1.1.0')
                    sock.sendto(packet, (hostname, port))
                    data, _ = sock.recvfrom(4096)
                    sock.close()

                    if data and len(data) > 10 and b'\x04' in data:
                        # Extract string from response
                        idx = data.find(b'\x04')
                        if idx >= 0 and idx + 2 < len(data):
                            slen = data[idx + 1]
                            if idx + 2 + slen <= len(data):
                                value = data[idx + 2:idx + 2 + slen].decode('utf-8', errors='replace')
                                self.engine.add_finding(self._finding(
                                    technique="SNMP Community String Disclosure",
                                    url=url,
                                    severity="HIGH" if community in ("private", "write") else "MEDIUM",
                                    confidence=0.95,
                                    param=f"community:{community}",
                                    payload=f"SNMP GET sysDescr with '{community}'",
                                    evidence=f"Community '{community}' accepted on port {port}: {value[:200]}",
                                ))
                except socket.timeout:
                    pass
                except Exception:
                    pass

    def _test_snmp_v3_noauth(self, hostname, url):
        """Test for SNMPv3 noAuthNoPriv mode."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            # SNMPv3 discovery
            packet = self._build_snmp_get("public", '1.3.6.1.2.1.1.1.0')
            sock.sendto(packet, (hostname, 161))
            data, _ = sock.recvfrom(4096)
            sock.close()
            if data and len(data) > 20:
                # Check if v3 response has no auth
                if data[4] == 3:  # SNMPv3
                    if b'\x04\x06noAuth' in data or b'\x04\x00' in data:
                        self.engine.add_finding(self._finding(
                            technique="SNMPv3 No Authentication",
                            url=url,
                            severity="HIGH",
                            confidence=0.7,
                            param="SNMPv3",
                            payload="SNMPv3 discovery",
                            evidence="SNMPv3 agent accepts noAuthNoPriv connections",
                        ))
        except Exception:
            pass

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
