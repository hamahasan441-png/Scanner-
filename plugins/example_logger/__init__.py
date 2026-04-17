"""
Example Logger Plugin for ATOMIC Framework

Demonstrates the plugin lifecycle hook system.  This plugin logs scan
events to a JSON file for external consumption (SIEM integration,
audit trail, etc.).

Lifecycle hooks implemented:
  - on_scan_start(**kwargs)   — called when a scan begins
  - on_finding(**kwargs)      — called for each vulnerability found
  - on_scan_complete(**kwargs) — called when a scan finishes

Usage:
    Drop this folder into the ``plugins/`` directory and the
    PluginManager will auto-discover and register the hooks.
"""

import json
import os
import time

plugin_info = {
    "name": "example_logger",
    "version": "1.0.0",
    "author": "ATOMIC Security",
    "description": "Example plugin that logs scan events to a JSON file",
    "category": "utility",
}


class PluginScanner:
    """Scan event logger — writes events to ``scan_events.jsonl``."""

    def __init__(self):
        self.engine = None
        self._log_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "logs",
            "scan_events.jsonl",
        )

    def setup(self, engine):
        """Receive a reference to the main AtomicEngine."""
        self.engine = engine
        os.makedirs(os.path.dirname(self._log_path), exist_ok=True)

    def run(self, target, params=None):
        """No-op — this plugin only uses lifecycle hooks."""
        return []

    # ------------------------------------------------------------------
    # Lifecycle hooks (auto-registered by PluginManager)
    # ------------------------------------------------------------------

    def on_scan_start(self, **kwargs):
        """Log scan start event."""
        self._write_event("scan_start", kwargs)

    def on_finding(self, **kwargs):
        """Log each finding event."""
        self._write_event("finding", kwargs)

    def on_scan_complete(self, **kwargs):
        """Log scan completion event."""
        self._write_event("scan_complete", kwargs)

    def teardown(self):
        """Cleanup."""
        self.engine = None

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _write_event(self, event_type, data):
        """Append a JSON-lines event to the log file."""
        entry = {
            "timestamp": time.time(),
            "event": event_type,
        }
        # Include only serialisable values from kwargs
        for key, value in data.items():
            try:
                json.dumps(value)
                entry[key] = value
            except (TypeError, ValueError):
                entry[key] = str(value)
        try:
            with open(self._log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        except OSError:
            pass
