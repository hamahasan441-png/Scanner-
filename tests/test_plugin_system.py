#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for core/plugin_system.py — Plugin architecture."""

import os
import sys
import shutil
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.plugin_system import PluginManager, PluginInfo, PluginResult


class TestPluginInfo(unittest.TestCase):
    """Test PluginInfo dataclass."""

    def test_to_dict(self):
        info = PluginInfo(
            name="test-plugin",
            version="1.0.0",
            author="tester",
            description="A test plugin",
            category="scanner",
            enabled=True,
        )
        d = info.to_dict()
        self.assertEqual(d["name"], "test-plugin")
        self.assertEqual(d["version"], "1.0.0")
        self.assertEqual(d["category"], "scanner")
        self.assertNotIn("instance", d)  # should not leak instance


class TestPluginResult(unittest.TestCase):
    """Test PluginResult dataclass."""

    def test_to_dict(self):
        r = PluginResult(
            plugin_name="test",
            success=True,
            findings=[{"type": "vuln"}],
            duration_seconds=1.5,
        )
        d = r.to_dict()
        self.assertEqual(d["plugin_name"], "test")
        self.assertTrue(d["success"])
        self.assertEqual(d["findings_count"], 1)

    def test_error_result(self):
        r = PluginResult(plugin_name="bad", success=False, error="crashed")
        d = r.to_dict()
        self.assertFalse(d["success"])
        self.assertEqual(d["error"], "crashed")


class TestPluginManager(unittest.TestCase):
    """Test PluginManager core functionality."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.manager = PluginManager(plugin_dir=self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_discover_empty_dir(self):
        discovered = self.manager.discover_plugins()
        self.assertEqual(discovered, [])

    def test_discover_nonexistent_dir(self):
        manager = PluginManager(plugin_dir="/nonexistent/path")
        self.assertEqual(manager.discover_plugins(), [])

    def test_discover_plugin(self):
        # Create a valid plugin directory
        plugin_dir = os.path.join(self.tmpdir, "my_plugin")
        os.makedirs(plugin_dir)
        with open(os.path.join(plugin_dir, "__init__.py"), "w") as f:
            f.write("plugin_info = {'name': 'my_plugin', 'version': '1.0'}\n")
        discovered = self.manager.discover_plugins()
        self.assertIn("my_plugin", discovered)

    def test_load_plugin(self):
        plugin_dir = os.path.join(self.tmpdir, "loadable")
        os.makedirs(plugin_dir)
        with open(os.path.join(plugin_dir, "__init__.py"), "w") as f:
            f.write("""
plugin_info = {'name': 'loadable', 'version': '2.0', 'author': 'test'}

class PluginScanner:
    def setup(self, engine):
        pass
    def run(self, target, params):
        return [{'type': 'test_finding'}]
    def teardown(self):
        pass
""")
        info = self.manager.load_plugin("loadable")
        self.assertIsNotNone(info)
        self.assertEqual(info.name, "loadable")
        self.assertEqual(info.version, "2.0")

    def test_load_nonexistent_plugin(self):
        info = self.manager.load_plugin("nonexistent")
        self.assertIsNone(info)

    def test_load_all(self):
        for name in ["p1", "p2"]:
            d = os.path.join(self.tmpdir, name)
            os.makedirs(d)
            with open(os.path.join(d, "__init__.py"), "w") as f:
                f.write(f"plugin_info = {{'name': '{name}'}}\n")
        count = self.manager.load_all()
        self.assertEqual(count, 2)

    def test_register_programmatic(self):
        class MockScanner:
            def run(self, target, params):
                return []

        info = self.manager.register("mock", MockScanner(), version="3.0")
        self.assertEqual(info.name, "mock")
        self.assertEqual(info.version, "3.0")

    def test_unregister(self):
        class MockScanner:
            teardown_called = False

            def teardown(self):
                MockScanner.teardown_called = True

        self.manager.register("removable", MockScanner())
        self.assertTrue(self.manager.unregister("removable"))
        self.assertFalse(self.manager.unregister("removable"))

    def test_list_plugins(self):
        self.manager.register("a", None)
        self.manager.register("b", None)
        plugins = self.manager.list_plugins()
        self.assertEqual(len(plugins), 2)
        names = {p["name"] for p in plugins}
        self.assertEqual(names, {"a", "b"})

    def test_get_plugin(self):
        self.manager.register("found", None)
        self.assertIsNotNone(self.manager.get_plugin("found"))
        self.assertIsNone(self.manager.get_plugin("missing"))

    def test_toggle_plugin(self):
        self.manager.register("toggle", None)
        self.assertTrue(self.manager.toggle_plugin("toggle", False))
        self.assertFalse(self.manager.get_plugin("toggle").enabled)
        self.assertFalse(self.manager.toggle_plugin("missing", True))

    def test_run_plugin(self):
        class TestScanner:
            def run(self, target, params):
                return [{"type": "found_it"}]

        self.manager.register("runner", TestScanner())
        result = self.manager.run_plugin("runner", "https://example.com")
        self.assertTrue(result.success)
        self.assertEqual(len(result.findings), 1)

    def test_run_plugin_disabled(self):
        self.manager.register("disabled", None)
        self.manager.toggle_plugin("disabled", False)
        result = self.manager.run_plugin("disabled", "https://example.com")
        self.assertFalse(result.success)

    def test_run_plugin_error(self):
        class BadScanner:
            def run(self, target, params):
                raise RuntimeError("plugin crash")

        self.manager.register("crasher", BadScanner())
        result = self.manager.run_plugin("crasher", "https://example.com")
        self.assertFalse(result.success)
        self.assertIn("plugin crash", result.error)

    def test_run_plugin_nonexistent(self):
        result = self.manager.run_plugin("ghost", "https://example.com")
        self.assertFalse(result.success)

    def test_run_all(self):
        class S1:
            def run(self, target, params):
                return [{"type": "1"}]

        class S2:
            def run(self, target, params):
                return [{"type": "2"}]

        self.manager.register("s1", S1(), category="scanner")
        self.manager.register("s2", S2(), category="recon")
        results = self.manager.run_all("https://example.com")
        self.assertEqual(len(results), 2)

    def test_run_all_by_category(self):
        class S:
            def run(self, target, params):
                return []

        self.manager.register("scan1", S(), category="scanner")
        self.manager.register("recon1", S(), category="recon")
        results = self.manager.run_all("https://example.com", category="scanner")
        self.assertEqual(len(results), 1)

    def test_hook_system(self):
        received = []
        self.manager.register_hook("pre_scan", lambda **kw: received.append(kw))
        self.manager.fire_hook("pre_scan", target="https://example.com")
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0]["target"], "https://example.com")

    def test_hook_error_handled(self):
        def bad_hook(**kw):
            raise RuntimeError("hook crash")

        self.manager.register_hook("post_scan", bad_hook)
        # Should not raise
        self.manager.fire_hook("post_scan")

    def test_invalid_hook_name(self):
        result = self.manager.register_hook("nonexistent_hook", lambda: None)
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
