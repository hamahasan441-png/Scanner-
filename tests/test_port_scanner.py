#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the Port Scanner module."""

import unittest

from modules.port_scanner import parse_port_spec, WELL_KNOWN_PORTS, TOP_100_PORTS


class TestParsePortSpec(unittest.TestCase):
    """Validate the port specification parser."""

    def test_single_port(self):
        self.assertEqual(parse_port_spec("80"), [80])

    def test_comma_separated(self):
        self.assertEqual(parse_port_spec("80,443,8080"), [80, 443, 8080])

    def test_range(self):
        result = parse_port_spec("20-25")
        self.assertEqual(result, [20, 21, 22, 23, 24, 25])

    def test_mixed_range_and_ports(self):
        result = parse_port_spec("80,443,8000-8002")
        self.assertEqual(result, [80, 443, 8000, 8001, 8002])

    def test_whitespace_tolerance(self):
        self.assertEqual(parse_port_spec(" 80 , 443 "), [80, 443])

    def test_empty_string(self):
        self.assertEqual(parse_port_spec(""), [])

    def test_invalid_port_zero(self):
        self.assertEqual(parse_port_spec("0"), [])

    def test_invalid_port_negative(self):
        self.assertEqual(parse_port_spec("-1"), [])

    def test_invalid_port_too_high(self):
        self.assertEqual(parse_port_spec("70000"), [])

    def test_invalid_non_numeric(self):
        self.assertEqual(parse_port_spec("abc"), [])

    def test_deduplication(self):
        result = parse_port_spec("80,80,80")
        self.assertEqual(result, [80])

    def test_sorted_output(self):
        result = parse_port_spec("443,80,22")
        self.assertEqual(result, [22, 80, 443])

    def test_range_boundary(self):
        result = parse_port_spec("65534-65535")
        self.assertEqual(result, [65534, 65535])


class TestWellKnownPorts(unittest.TestCase):
    """Sanity checks on the constant tables."""

    def test_contains_common_ports(self):
        for port in (22, 80, 443, 3306, 8080):
            self.assertIn(port, WELL_KNOWN_PORTS)

    def test_top100_not_empty(self):
        self.assertTrue(len(TOP_100_PORTS) > 10)


class TestPortScannerInit(unittest.TestCase):
    """Verify PortScanner construction."""

    def test_instantiation(self):
        from modules.port_scanner import PortScanner

        class _Eng:
            config = {"timeout": 3, "threads": 10, "verbose": False}
            requester = None

        scanner = PortScanner(_Eng())
        self.assertEqual(scanner.timeout, 3)
        self.assertEqual(scanner.threads, 10)

    def test_timeout_cap(self):
        from modules.port_scanner import PortScanner

        class _Eng:
            config = {"timeout": 30, "threads": 10, "verbose": False}
            requester = None

        scanner = PortScanner(_Eng())
        self.assertLessEqual(scanner.timeout, 5)


if __name__ == "__main__":
    unittest.main()
