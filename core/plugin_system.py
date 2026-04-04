#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Plugin System
Extensible plugin architecture for third-party scanning modules.

Plugin structure:
  plugins/
    my_plugin/
      __init__.py   # contains plugin_info dict
      scanner.py    # contains PluginScanner class

Plugin interface:
  class PluginScanner:
      name: str
      description: str
      def setup(self, engine) -> None
      def run(self, target: str, params: list) -> list[dict]
      def teardown(self) -> None

Plugin registration:
  - Drop-in: place plugin folder in ``plugins/`` directory
  - API: call ``plugin_manager.register(plugin_instance)``
"""

import importlib
import importlib.util
import os
import sys
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class PluginInfo:
    """Metadata about a registered plugin."""
    name: str
    version: str = '1.0.0'
    author: str = ''
    description: str = ''
    category: str = 'scanner'   # scanner | recon | exploit | report | utility
    enabled: bool = True
    loaded_at: str = ''
    module_path: str = ''
    instance: Any = None

    def to_dict(self) -> dict:
        return {
            'name': self.name,
            'version': self.version,
            'author': self.author,
            'description': self.description,
            'category': self.category,
            'enabled': self.enabled,
            'loaded_at': self.loaded_at,
            'module_path': self.module_path,
        }


@dataclass
class PluginResult:
    """Result from a plugin execution."""
    plugin_name: str
    success: bool
    findings: List[dict] = field(default_factory=list)
    data: dict = field(default_factory=dict)
    error: str = ''
    duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            'plugin_name': self.plugin_name,
            'success': self.success,
            'findings_count': len(self.findings),
            'findings': self.findings,
            'data': self.data,
            'error': self.error,
            'duration_seconds': self.duration_seconds,
        }


class PluginManager:
    """Discover, load, and manage scanner plugins."""

    def __init__(self, plugin_dir: str = ''):
        self._plugins: Dict[str, PluginInfo] = {}
        self._lock = threading.Lock()
        self._plugin_dir = plugin_dir or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'plugins',
        )
        self._hooks: Dict[str, List] = {
            'pre_scan': [],
            'post_scan': [],
            'on_finding': [],
            'pre_report': [],
        }

    # --- Discovery & Loading ---

    def discover_plugins(self) -> List[str]:
        """Scan the plugin directory for available plugins."""
        discovered = []
        if not os.path.isdir(self._plugin_dir):
            return discovered

        for entry in os.listdir(self._plugin_dir):
            plugin_path = os.path.join(self._plugin_dir, entry)
            init_path = os.path.join(plugin_path, '__init__.py')
            if os.path.isdir(plugin_path) and os.path.isfile(init_path):
                discovered.append(entry)
        return discovered

    def load_plugin(self, plugin_name: str) -> Optional[PluginInfo]:
        """Load a plugin from the plugins directory by name."""
        plugin_path = os.path.join(self._plugin_dir, plugin_name)
        init_path = os.path.join(plugin_path, '__init__.py')

        if not os.path.isfile(init_path):
            return None

        try:
            # Add plugin dir to path temporarily
            if plugin_path not in sys.path:
                sys.path.insert(0, plugin_path)

            spec = importlib.util.spec_from_file_location(
                f"plugins.{plugin_name}", init_path,
            )
            if spec is None or spec.loader is None:
                return None

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # Extract plugin_info dict
            info_dict = getattr(module, 'plugin_info', {})
            scanner_class = getattr(module, 'PluginScanner', None)

            instance = None
            if scanner_class:
                instance = scanner_class()

            plugin_info = PluginInfo(
                name=info_dict.get('name', plugin_name),
                version=info_dict.get('version', '1.0.0'),
                author=info_dict.get('author', ''),
                description=info_dict.get('description', ''),
                category=info_dict.get('category', 'scanner'),
                enabled=True,
                loaded_at=datetime.now(timezone.utc).isoformat(),
                module_path=plugin_path,
                instance=instance,
            )

            with self._lock:
                self._plugins[plugin_info.name] = plugin_info

            return plugin_info
        except Exception:
            return None

    def load_all(self) -> int:
        """Discover and load all plugins. Returns count of loaded plugins."""
        count = 0
        for name in self.discover_plugins():
            if self.load_plugin(name):
                count += 1
        return count

    # --- Registration (programmatic) ---

    def register(self, name: str, instance: Any, **kwargs) -> PluginInfo:
        """Register a plugin programmatically."""
        info = PluginInfo(
            name=name,
            version=kwargs.get('version', '1.0.0'),
            author=kwargs.get('author', ''),
            description=kwargs.get('description', ''),
            category=kwargs.get('category', 'scanner'),
            enabled=True,
            loaded_at=datetime.now(timezone.utc).isoformat(),
            instance=instance,
        )
        with self._lock:
            self._plugins[name] = info
        return info

    def unregister(self, name: str) -> bool:
        with self._lock:
            plugin = self._plugins.pop(name, None)
        if plugin and plugin.instance and hasattr(plugin.instance, 'teardown'):
            try:
                plugin.instance.teardown()
            except Exception:
                pass
        return plugin is not None

    # --- Query ---

    def list_plugins(self) -> List[dict]:
        with self._lock:
            return [p.to_dict() for p in self._plugins.values()]

    def get_plugin(self, name: str) -> Optional[PluginInfo]:
        return self._plugins.get(name)

    def toggle_plugin(self, name: str, enabled: bool) -> bool:
        plugin = self._plugins.get(name)
        if not plugin:
            return False
        plugin.enabled = enabled
        return True

    # --- Execution ---

    def run_plugin(self, name: str, target: str, params: Optional[list] = None,
                   engine: Any = None) -> PluginResult:
        """Execute a single plugin."""
        import time
        plugin = self._plugins.get(name)
        if not plugin or not plugin.enabled or not plugin.instance:
            return PluginResult(plugin_name=name, success=False,
                                error='Plugin not available or disabled')

        start = time.time()
        try:
            if hasattr(plugin.instance, 'setup') and engine:
                plugin.instance.setup(engine)
            findings = plugin.instance.run(target, params or [])
            duration = time.time() - start
            return PluginResult(
                plugin_name=name,
                success=True,
                findings=findings if isinstance(findings, list) else [],
                duration_seconds=round(duration, 2),
            )
        except Exception as exc:
            duration = time.time() - start
            return PluginResult(
                plugin_name=name,
                success=False,
                error=str(exc),
                duration_seconds=round(duration, 2),
            )

    def run_all(self, target: str, params: Optional[list] = None,
                engine: Any = None, category: str = '') -> List[PluginResult]:
        """Run all enabled plugins (optionally filtered by category)."""
        results = []
        for name, plugin in self._plugins.items():
            if not plugin.enabled:
                continue
            if category and plugin.category != category:
                continue
            results.append(self.run_plugin(name, target, params, engine))
        return results

    # --- Hook System ---

    def register_hook(self, hook_name: str, callback) -> bool:
        """Register a callback for a lifecycle hook."""
        if hook_name not in self._hooks:
            return False
        self._hooks[hook_name].append(callback)
        return True

    def fire_hook(self, hook_name: str, **kwargs):
        """Fire all callbacks for a lifecycle hook."""
        for cb in self._hooks.get(hook_name, []):
            try:
                cb(**kwargs)
            except Exception:
                pass
