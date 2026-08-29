#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - ICS/SCADA Protocol Module
Modbus, BACnet, DNP3, OPC UA, Profinet, EtherNet/IP detection.
"""
import socket
from config import Colors
from modules.base import BaseModule


class ICSProtocolModule(BaseModule):
    """ICS/SCADA protocol detection module."""

    name = "ICS/SCADA Protocols"
    vuln_type = "ics"

    ICS_PORTS = {
        502: "Modbus",
        47808: "BACnet",
        20000: "DNP3",
        4840: "OPC UA",
        34962: "Profinet",
        44818: "EtherNet/IP",
        1883: "MQTT",
        5683: "CoAP",
        9600: "OMRON FINS",
        102: "Siemens S7",
        4840: "OPC UA",
    }

    def test_url(self, url):
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname or url
        if not hostname:
            return
        self._test_ics_ports(hostname, url)

    def test(self, url, method, param, value):
        pass

    def _test_ics_ports(self, hostname, url):
        """Test for open ICS/SCADA ports."""
        for port, proto in self.ICS_PORTS.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((hostname, port))
                sock.close()
                if result == 0:
                    sev = "CRITICAL" if proto in ("Modbus", "Siemens S7", "DNP3") else "HIGH"
                    self.engine.add_finding(self._finding(
                        technique=f"ICS Port Open ({proto})",
                        url=url,
                        severity=sev,
                        confidence=0.8,
                        param=f"port:{port}",
                        payload=f"TCP connect {port}",
                        evidence=f"Industrial protocol {proto} on port {port}",
                    ))
                    self._test_modbus(hostname, url, port, proto)
            except Exception:
                pass

    def _test_modbus(self, hostname, url, port, proto):
        """Test Modbus for default access."""
        if proto != "Modbus":
            return
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((hostname, port))
            # Modbus TCP: MBAP header + Unit ID + Function Code
            # Read device identification (function code 43)
            mbap = b'\x00\x01\x00\x00\x00\x06\x01\x2b\x0e\x01\x00'
            sock.send(mbap)
            data = sock.recv(4096)
            sock.close()
            if data and len(data) > 10:
                self.engine.add_finding(self._finding(
                    technique="Modbus Default Access",
                    url=url,
                    severity="CRITICAL",
                    confidence=0.7,
                    param=f"port:{port}",
                    payload="Modbus read device ID",
                    evidence=f"Modbus device responded: {data.hex()[:100]}",
                ))
        except Exception:
            pass

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
