#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v11.0 — Plugin Hot-Reload
==========================================

Watches the ``plugins/`` directory with a background thread.
New ``.py`` plugin files and new plugin directories are auto-loaded
without restarting the framework.

Uses the ``watchdog`` library when available; falls back to a simple
polling loop otherwise.

Usage::

    from core.plugin_hotreload import PluginHotReloader
    reloader = PluginHotReloader(plugin_manager)
    reloader.start()          # start background watcher
    # ... framework runs ...
    reloader.stop()           # stop watcher on shutdown
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import TYPE_CHECKING, Set

if TYPE_CHECKING:
    from core.plugin_system import PluginManager

logger = logging.getLogger(__name__)

_WATCHDOG_AVAILABLE = False
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    _WATCHDOG_AVAILABLE = True
except ImportError:
    pass

POLL_INTERVAL = 5  # seconds between directory polls (fallback)


# ---------------------------------------------------------------------------
# Watchdog-based handler
# ---------------------------------------------------------------------------

if _WATCHDOG_AVAILABLE:
    class _PluginEventHandler(FileSystemEventHandler):
        """watchdog event handler that triggers plugin reload."""

        def __init__(self, reloader: "PluginHotReloader"):
            super().__init__()
            self.reloader = reloader

        def on_created(self, event):
            if not event.is_directory:
                return
            plugin_dir = event.src_path
            name = os.path.basename(plugin_dir)
            init_path = os.path.join(plugin_dir, "__init__.py")
            if os.path.isfile(init_path):
                logger.info("[HOT-RELOAD] New plugin directory detected: %s", name)
                self.reloader._load_plugin(name)

        def on_modified(self, event):
            if event.is_directory:
                return
            path = event.src_path
            # __init__.py modified → reload the plugin
            if os.path.basename(path) == "__init__.py":
                plugin_dir = os.path.dirname(path)
                name = os.path.basename(plugin_dir)
                parent = os.path.dirname(plugin_dir)
                if parent == self.reloader._plugin_dir:
                    logger.info("[HOT-RELOAD] Plugin modified: %s — reloading", name)
                    self.reloader._reload_plugin(name)


# ---------------------------------------------------------------------------
# Hot-reloader
# ---------------------------------------------------------------------------


class PluginHotReloader:
    """Background plugin directory watcher.

    Uses watchdog when available, otherwise polls every POLL_INTERVAL seconds.
    """

    def __init__(self, plugin_manager: "PluginManager"):
        self.plugin_manager = plugin_manager
        self._plugin_dir = plugin_manager._plugin_dir
        self._known_plugins: Set[str] = set(plugin_manager._plugins.keys())
        self._thread: threading.Thread | None = None
        self._observer = None
        self._stop_event = threading.Event()

    # ------------------------------------------------------------------
    # Start / stop
    # ------------------------------------------------------------------

    def start(self):
        """Start the hot-reload watcher in a background thread."""
        if _WATCHDOG_AVAILABLE:
            self._start_watchdog()
        else:
            self._start_poll()

    def stop(self):
        """Stop the watcher."""
        self._stop_event.set()
        if self._observer:
            try:
                self._observer.stop()
                self._observer.join(timeout=5)
            except Exception:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

    # ------------------------------------------------------------------
    # Watchdog backend
    # ------------------------------------------------------------------

    def _start_watchdog(self):
        """Start a watchdog Observer watching the plugin directory."""
        if not os.path.isdir(self._plugin_dir):
            return
        handler = _PluginEventHandler(self)
        self._observer = Observer()
        self._observer.schedule(handler, self._plugin_dir, recursive=True)
        self._observer.start()
        logger.info("[HOT-RELOAD] watchdog observer started on %s", self._plugin_dir)

    # ------------------------------------------------------------------
    # Poll backend (fallback)
    # ------------------------------------------------------------------

    def _start_poll(self):
        """Start a background polling thread."""
        self._thread = threading.Thread(
            target=self._poll_loop,
            name="plugin-hotreload",
            daemon=True,
        )
        self._thread.start()
        logger.info("[HOT-RELOAD] polling thread started (interval=%ds)", POLL_INTERVAL)

    def _poll_loop(self):
        """Periodically check the plugin directory for new plugins."""
        while not self._stop_event.is_set():
            try:
                self._check_for_new_plugins()
            except Exception as exc:
                logger.debug("[HOT-RELOAD] poll error: %s", exc)
            self._stop_event.wait(timeout=POLL_INTERVAL)

    def _check_for_new_plugins(self):
        """Detect new plugin directories and load them."""
        if not os.path.isdir(self._plugin_dir):
            return

        for entry in os.listdir(self._plugin_dir):
            plugin_path = os.path.join(self._plugin_dir, entry)
            init_path = os.path.join(plugin_path, "__init__.py")
            if (
                os.path.isdir(plugin_path)
                and os.path.isfile(init_path)
                and entry not in self._known_plugins
            ):
                logger.info("[HOT-RELOAD] New plugin detected: %s", entry)
                self._load_plugin(entry)

    # ------------------------------------------------------------------
    # Load / reload
    # ------------------------------------------------------------------

    def _load_plugin(self, name: str):
        """Load a new plugin into the manager."""
        try:
            info = self.plugin_manager.load_plugin(name)
            if info:
                self._known_plugins.add(name)
                from config import Colors
                print(
                    f"{Colors.success(f'[HOT-RELOAD] Plugin loaded: {name} v{info.version}')}"
                )
        except Exception as exc:
            logger.warning("[HOT-RELOAD] Failed to load plugin %s: %s", name, exc)

    def _reload_plugin(self, name: str):
        """Reload an already-loaded plugin."""
        try:
            self.plugin_manager.unload_plugin(name)
        except Exception:
            pass
        self._load_plugin(name)
