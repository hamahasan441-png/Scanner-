#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Notification System
Multi-channel alerting for scan events, findings, and system status.

Channels:
  - Webhook    (generic HTTP POST — compatible with Slack, Discord, Teams, custom)
  - Console    (stdout logging)

Each notification includes: severity, title, message, metadata.
"""

import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

try:
    import requests as _requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Notification data types
# ---------------------------------------------------------------------------
class NotifySeverity:
    INFO = 'info'
    WARNING = 'warning'
    CRITICAL = 'critical'
    SUCCESS = 'success'


@dataclass
class Notification:
    """A notification message."""
    title: str = ''
    message: str = ''
    severity: str = 'info'
    channel: str = ''
    metadata: dict = field(default_factory=dict)
    timestamp: str = ''

    def to_dict(self) -> dict:
        return {
            'title': self.title,
            'message': self.message,
            'severity': self.severity,
            'channel': self.channel,
            'metadata': self.metadata,
            'timestamp': self.timestamp,
        }


# ---------------------------------------------------------------------------
# Channel Adapters
# ---------------------------------------------------------------------------
class ConsoleChannel:
    """Print notifications to stdout."""

    name = 'console'

    def send(self, notification: Notification) -> bool:
        severity_map = {
            'info': '\033[94m[INFO]\033[0m',
            'warning': '\033[93m[WARN]\033[0m',
            'critical': '\033[91m[CRIT]\033[0m',
            'success': '\033[92m[ OK ]\033[0m',
        }
        prefix = severity_map.get(notification.severity, '[????]')
        print(f"{prefix} {notification.title}: {notification.message}")
        return True


class WebhookChannel:
    """Send notifications via HTTP webhook (Slack/Discord/Teams/custom)."""

    name = 'webhook'

    def __init__(self, url: str = '', headers: Optional[dict] = None,
                 format_type: str = 'generic'):
        self.url = url or os.environ.get('ATOMIC_WEBHOOK_URL', '')
        self.headers = headers or {'Content-Type': 'application/json'}
        self.format_type = format_type  # generic | slack | discord | teams

    def send(self, notification: Notification) -> bool:
        if not self.url or not REQUESTS_AVAILABLE:
            return False

        payload = self._format_payload(notification)
        try:
            resp = _requests.post(
                self.url,
                json=payload,
                headers=self.headers,
                timeout=10,
            )
            return 200 <= resp.status_code < 300
        except Exception as exc:
            logger.warning('Webhook notification failed: %s', exc)
            return False

    def _format_payload(self, notification: Notification) -> dict:
        if self.format_type == 'slack':
            emoji = {'critical': ':rotating_light:', 'warning': ':warning:',
                     'success': ':white_check_mark:', 'info': ':information_source:'}
            return {
                'text': f"{emoji.get(notification.severity, ':bell:')} *{notification.title}*\n{notification.message}",
            }
        elif self.format_type == 'discord':
            color_map = {'critical': 0xFF0000, 'warning': 0xFFAA00,
                         'success': 0x00FF00, 'info': 0x0099FF}
            return {
                'embeds': [{
                    'title': notification.title,
                    'description': notification.message,
                    'color': color_map.get(notification.severity, 0x999999),
                    'timestamp': notification.timestamp,
                }],
            }
        elif self.format_type == 'teams':
            return {
                '@type': 'MessageCard',
                'summary': notification.title,
                'themeColor': {'critical': 'FF0000', 'warning': 'FFAA00',
                               'success': '00FF00', 'info': '0099FF'}.get(notification.severity, '999999'),
                'title': notification.title,
                'text': notification.message,
            }
        else:
            return notification.to_dict()


# ---------------------------------------------------------------------------
# Notification Manager
# ---------------------------------------------------------------------------
class NotificationManager:
    """Central notification dispatcher."""

    def __init__(self):
        self._channels: Dict[str, object] = {}
        self._history: List[dict] = []
        self._lock = threading.Lock()
        self._rules: List[dict] = []
        self._enabled = True

        # Always register console
        self.register_channel('console', ConsoleChannel())

        # Auto-register webhook if URL is configured
        webhook_url = os.environ.get('ATOMIC_WEBHOOK_URL', '')
        if webhook_url:
            fmt = os.environ.get('ATOMIC_WEBHOOK_FORMAT', 'generic')
            self.register_channel('webhook', WebhookChannel(url=webhook_url, format_type=fmt))

    def register_channel(self, name: str, channel: object) -> None:
        """Register a notification channel."""
        self._channels[name] = channel

    def unregister_channel(self, name: str) -> bool:
        return self._channels.pop(name, None) is not None

    def list_channels(self) -> List[str]:
        return list(self._channels.keys())

    def add_rule(self, severity: str = '', category: str = '', channels: Optional[List[str]] = None):
        """Add a routing rule: match severity/category → send to specific channels."""
        self._rules.append({
            'severity': severity,
            'category': category,
            'channels': channels or list(self._channels.keys()),
        })

    def notify(self, title: str, message: str, severity: str = NotifySeverity.INFO,
               metadata: Optional[dict] = None, channels: Optional[List[str]] = None) -> List[bool]:
        """Send a notification to specified channels (or all if not specified)."""
        if not self._enabled:
            return []

        notification = Notification(
            title=title,
            message=message,
            severity=severity,
            metadata=metadata or {},
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        target_channels = channels or list(self._channels.keys())
        results = []

        for ch_name in target_channels:
            channel = self._channels.get(ch_name)
            if not channel:
                continue
            notification.channel = ch_name
            try:
                success = channel.send(notification)
                results.append(success)
            except Exception:
                results.append(False)

        # Record in history
        with self._lock:
            self._history.append({
                **notification.to_dict(),
                'sent_to': target_channels,
                'results': results,
            })
            if len(self._history) > 500:
                self._history = self._history[-500:]

        return results

    # --- Convenience methods ---

    def notify_scan_started(self, scan_id: str, target: str, **kwargs):
        return self.notify(
            title='Scan Started',
            message=f'Scan {scan_id} started for target: {target}',
            severity=NotifySeverity.INFO,
            metadata={'scan_id': scan_id, 'target': target, **kwargs},
        )

    def notify_scan_completed(self, scan_id: str, target: str, findings_count: int, **kwargs):
        sev = NotifySeverity.SUCCESS if findings_count == 0 else NotifySeverity.WARNING
        return self.notify(
            title='Scan Completed',
            message=f'Scan {scan_id} completed for {target}: {findings_count} findings',
            severity=sev,
            metadata={'scan_id': scan_id, 'target': target,
                      'findings_count': findings_count, **kwargs},
        )

    def notify_critical_finding(self, finding_technique: str, target: str, **kwargs):
        return self.notify(
            title='Critical Finding Detected',
            message=f'CRITICAL: {finding_technique} found on {target}',
            severity=NotifySeverity.CRITICAL,
            metadata={'technique': finding_technique, 'target': target, **kwargs},
        )

    def notify_scan_failed(self, scan_id: str, error: str, **kwargs):
        return self.notify(
            title='Scan Failed',
            message=f'Scan {scan_id} failed: {error}',
            severity=NotifySeverity.CRITICAL,
            metadata={'scan_id': scan_id, 'error': error, **kwargs},
        )

    def get_history(self, limit: int = 50) -> List[dict]:
        with self._lock:
            return list(reversed(self._history[-limit:]))

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool):
        self._enabled = value
