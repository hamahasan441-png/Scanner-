#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for core/notification.py — Notification system."""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.notification import (
    NotificationManager,
    Notification,
    ConsoleChannel,
    WebhookChannel,
)


class TestNotification(unittest.TestCase):
    """Test Notification dataclass."""

    def test_to_dict(self):
        n = Notification(
            title="Test",
            message="Hello",
            severity="info",
            channel="console",
            timestamp="2025-01-01T00:00:00Z",
        )
        d = n.to_dict()
        self.assertEqual(d["title"], "Test")
        self.assertEqual(d["message"], "Hello")
        self.assertEqual(d["severity"], "info")


class TestConsoleChannel(unittest.TestCase):
    """Test ConsoleChannel."""

    def test_send(self):
        ch = ConsoleChannel()
        n = Notification(title="Test", message="msg", severity="info")
        result = ch.send(n)
        self.assertTrue(result)

    def test_send_all_severities(self):
        ch = ConsoleChannel()
        for sev in ("info", "warning", "critical", "success"):
            n = Notification(title="Test", message="msg", severity=sev)
            self.assertTrue(ch.send(n))


class TestWebhookChannel(unittest.TestCase):
    """Test WebhookChannel."""

    def test_no_url_returns_false(self):
        ch = WebhookChannel(url="")
        n = Notification(title="Test", message="msg")
        result = ch.send(n)
        self.assertFalse(result)

    def test_generic_format(self):
        ch = WebhookChannel(url="https://example.com/hook", format_type="generic")
        n = Notification(title="Test", message="msg", severity="info", timestamp="2025-01-01T00:00:00Z")
        payload = ch._format_payload(n)
        self.assertIn("title", payload)
        self.assertEqual(payload["title"], "Test")

    def test_slack_format(self):
        ch = WebhookChannel(url="https://example.com/hook", format_type="slack")
        n = Notification(title="Alert", message="finding", severity="critical")
        payload = ch._format_payload(n)
        self.assertIn("text", payload)
        self.assertIn("Alert", payload["text"])

    def test_discord_format(self):
        ch = WebhookChannel(url="https://example.com/hook", format_type="discord")
        n = Notification(title="Alert", message="finding", severity="warning", timestamp="2025-01-01T00:00:00Z")
        payload = ch._format_payload(n)
        self.assertIn("embeds", payload)
        self.assertEqual(len(payload["embeds"]), 1)
        self.assertEqual(payload["embeds"][0]["title"], "Alert")

    def test_teams_format(self):
        ch = WebhookChannel(url="https://example.com/hook", format_type="teams")
        n = Notification(title="Alert", message="finding", severity="success")
        payload = ch._format_payload(n)
        self.assertEqual(payload["@type"], "MessageCard")
        self.assertEqual(payload["title"], "Alert")

    @patch("core.notification._requests")
    def test_send_success(self, mock_requests):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_requests.post.return_value = mock_response
        ch = WebhookChannel(url="https://example.com/hook")
        n = Notification(title="Test", message="msg", severity="info")
        result = ch.send(n)
        self.assertTrue(result)

    @patch("core.notification._requests")
    def test_send_failure(self, mock_requests):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_requests.post.return_value = mock_response
        ch = WebhookChannel(url="https://example.com/hook")
        n = Notification(title="Test", message="msg", severity="info")
        result = ch.send(n)
        self.assertFalse(result)


class TestNotificationManager(unittest.TestCase):
    """Test NotificationManager."""

    def setUp(self):
        # Clear env vars to prevent auto-registration
        self._orig = os.environ.get("ATOMIC_WEBHOOK_URL")
        os.environ.pop("ATOMIC_WEBHOOK_URL", None)
        self.manager = NotificationManager()

    def tearDown(self):
        if self._orig:
            os.environ["ATOMIC_WEBHOOK_URL"] = self._orig

    def test_console_registered_by_default(self):
        self.assertIn("console", self.manager.list_channels())

    def test_register_channel(self):
        ch = ConsoleChannel()
        self.manager.register_channel("extra", ch)
        self.assertIn("extra", self.manager.list_channels())

    def test_unregister_channel(self):
        self.manager.register_channel("rm", ConsoleChannel())
        self.assertTrue(self.manager.unregister_channel("rm"))
        self.assertFalse(self.manager.unregister_channel("rm"))

    def test_notify_basic(self):
        results = self.manager.notify("Test", "Hello World")
        self.assertIsInstance(results, list)
        self.assertTrue(all(results))

    def test_notify_specific_channel(self):
        results = self.manager.notify("Test", "msg", channels=["console"])
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0])

    def test_notify_nonexistent_channel(self):
        results = self.manager.notify("Test", "msg", channels=["ghost"])
        self.assertEqual(results, [])

    def test_notify_disabled(self):
        self.manager.enabled = False
        results = self.manager.notify("Test", "msg")
        self.assertEqual(results, [])

    def test_notify_scan_started(self):
        results = self.manager.notify_scan_started("abc123", "https://example.com")
        self.assertTrue(all(results))

    def test_notify_scan_completed(self):
        results = self.manager.notify_scan_completed("abc123", "https://example.com", 5)
        self.assertTrue(all(results))

    def test_notify_scan_completed_zero_findings(self):
        results = self.manager.notify_scan_completed("abc123", "https://example.com", 0)
        self.assertTrue(all(results))

    def test_notify_critical_finding(self):
        results = self.manager.notify_critical_finding("SQL Injection", "https://example.com")
        self.assertTrue(all(results))

    def test_notify_scan_failed(self):
        results = self.manager.notify_scan_failed("abc123", "Connection timeout")
        self.assertTrue(all(results))

    def test_history(self):
        self.manager.notify("Test1", "msg1")
        self.manager.notify("Test2", "msg2")
        history = self.manager.get_history()
        self.assertEqual(len(history), 2)
        # Most recent first
        self.assertEqual(history[0]["title"], "Test2")

    def test_history_limit(self):
        for i in range(10):
            self.manager.notify(f"Test{i}", "msg")
        history = self.manager.get_history(limit=3)
        self.assertEqual(len(history), 3)

    def test_enabled_property(self):
        self.assertTrue(self.manager.enabled)
        self.manager.enabled = False
        self.assertFalse(self.manager.enabled)


if __name__ == "__main__":
    unittest.main()
