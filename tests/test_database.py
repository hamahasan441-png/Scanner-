#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for utils/database.py"""

import unittest
from datetime import datetime, timezone
from config import Config


class _FakeFinding:
    """Minimal object that quacks like a Finding for save_finding()."""

    def __init__(self, **kwargs):
        defaults = dict(
            technique="SQL Injection",
            mitre_id="T1190",
            cwe_id="CWE-89",
            cvss=9.8,
            severity="Critical",
            confidence=0.95,
            url="http://example.com/vuln",
            param="id",
            payload="' OR 1=1 --",
            evidence="error in SQL syntax",
            extracted_data="admin:password",
        )
        defaults.update(kwargs)
        for k, v in defaults.items():
            setattr(self, k, v)


class TestDatabase(unittest.TestCase):
    """Tests for the Database class using an in-memory SQLite backend."""

    def setUp(self):
        self._orig_db_url = Config.DB_URL
        Config.DB_URL = "sqlite:///:memory:"
        from utils.database import Database
        self.db = Database()

    def tearDown(self):
        Config.DB_URL = self._orig_db_url

    # ------------------------------------------------------------------
    # __init__
    # ------------------------------------------------------------------
    def test_init_creates_engine_and_session(self):
        self.assertIsNotNone(self.db.engine)
        self.assertIsNotNone(self.db.Session)

    # ------------------------------------------------------------------
    # save_scan / update_scan
    # ------------------------------------------------------------------
    def test_save_scan_stores_record(self):
        self.db.save_scan(scan_id="scan-1", target="http://example.com")
        from utils.database import ScanModel
        session = self.db.Session()
        scan = session.query(ScanModel).filter_by(scan_id="scan-1").first()
        self.assertIsNotNone(scan)
        self.assertEqual(scan.target, "http://example.com")
        session.close()

    def test_save_scan_no_session(self):
        self.db.Session = None
        self.db.save_scan(scan_id="scan-x", target="http://example.com")

    def test_save_scan_duplicate_id_does_not_raise(self):
        self.db.save_scan(scan_id="dup-1", target="http://a.com")
        self.db.save_scan(scan_id="dup-1", target="http://b.com")

    def test_update_scan_modifies_fields(self):
        self.db.save_scan(scan_id="scan-2", target="http://example.com")
        now = datetime.now(timezone.utc)
        self.db.update_scan("scan-2", end_time=now, findings_count=5,
                            total_requests=100)
        from utils.database import ScanModel
        session = self.db.Session()
        scan = session.query(ScanModel).filter_by(scan_id="scan-2").first()
        self.assertEqual(scan.findings_count, 5)
        self.assertEqual(scan.total_requests, 100)
        self.assertIsNotNone(scan.end_time)
        session.close()

    def test_update_scan_nonexistent_id(self):
        self.db.update_scan("no-such-scan", findings_count=1)

    def test_update_scan_no_session(self):
        self.db.Session = None
        self.db.update_scan("scan-x", findings_count=1)

    # ------------------------------------------------------------------
    # save_finding
    # ------------------------------------------------------------------
    def test_save_finding_stores_record(self):
        self.db.save_scan(scan_id="scan-f", target="http://example.com")
        finding = _FakeFinding()
        self.db.save_finding("scan-f", finding)

        from utils.database import FindingModel
        session = self.db.Session()
        row = session.query(FindingModel).filter_by(scan_id="scan-f").first()
        self.assertIsNotNone(row)
        self.assertEqual(row.technique, "SQL Injection")
        self.assertAlmostEqual(row.cvss, 9.8, places=1)
        self.assertEqual(row.param, "id")
        session.close()

    def test_save_finding_no_session(self):
        self.db.Session = None
        self.db.save_finding("scan-x", _FakeFinding())

    # ------------------------------------------------------------------
    # save_shell / get_shells / update_shell
    # ------------------------------------------------------------------
    def test_save_shell_stores_record(self):
        self.db.save_shell(shell_id="sh-1", url="http://example.com/shell.php",
                           shell_type="php", password="secret")
        from utils.database import ShellModel
        session = self.db.Session()
        shell = session.query(ShellModel).filter_by(shell_id="sh-1").first()
        self.assertIsNotNone(shell)
        self.assertEqual(shell.shell_type, "php")
        self.assertEqual(shell.password, "secret")
        session.close()

    def test_save_shell_no_session(self):
        self.db.Session = None
        self.db.save_shell(shell_id="sh-x", url="http://x", shell_type="php")

    def test_get_shells_returns_active(self):
        self.db.save_shell(shell_id="sh-a", url="http://a.com/sh",
                           shell_type="php")
        self.db.save_shell(shell_id="sh-b", url="http://b.com/sh",
                           shell_type="cmd")
        shells = self.db.get_shells()
        self.assertEqual(len(shells), 2)
        ids = {s["shell_id"] for s in shells}
        self.assertEqual(ids, {"sh-a", "sh-b"})

    def test_get_shells_empty(self):
        shells = self.db.get_shells()
        self.assertEqual(shells, [])

    def test_get_shells_no_session(self):
        self.db.Session = None
        self.assertEqual(self.db.get_shells(), [])

    def test_update_shell_changes_status(self):
        self.db.save_shell(shell_id="sh-u", url="http://u.com/sh",
                           shell_type="php")
        self.db.update_shell("sh-u", status="inactive")

        from utils.database import ShellModel
        session = self.db.Session()
        shell = session.query(ShellModel).filter_by(shell_id="sh-u").first()
        self.assertEqual(shell.status, "inactive")
        session.close()

    def test_update_shell_inactive_not_returned(self):
        self.db.save_shell(shell_id="sh-gone", url="http://g.com/sh",
                           shell_type="php")
        self.db.update_shell("sh-gone", status="inactive")
        shells = self.db.get_shells()
        self.assertEqual(shells, [])

    def test_update_shell_nonexistent_id(self):
        self.db.update_shell("no-such-shell", status="inactive")

    def test_update_shell_no_session(self):
        self.db.Session = None
        self.db.update_shell("sh-x", status="inactive")


if __name__ == "__main__":
    unittest.main()
