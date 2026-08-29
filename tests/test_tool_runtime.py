import hashlib
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.tool_runtime import ToolRuntime


class TestToolRuntime(unittest.TestCase):
    def test_missing_manifest_is_safe(self):
        with tempfile.TemporaryDirectory() as td:
            runtime = ToolRuntime(td)
            self.assertIsNone(runtime.bundled_path("nuclei"))

    def test_bundled_tool_requires_integrity_when_pinned(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            b = root / "runtime" / "bin"
            m = root / "runtime" / "metadata"
            b.mkdir(parents=True)
            m.mkdir(parents=True)
            tool = b / "fake"
            tool.write_text("#!/bin/sh\nprintf ok\n")
            tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
            good = hashlib.sha256(tool.read_bytes()).hexdigest()
            (m / "tools.json").write_text('{"tools":{"fake":{"binary":"fake","sha256":"%s"}}}' % good)
            runtime = ToolRuntime(td)
            self.assertEqual(runtime.bundled_path("fake"), str(tool))

            (m / "tools.json").write_text('{"tools":{"fake":{"binary":"fake","sha256":"deadbeef"}}}')
            runtime = ToolRuntime(td)
            self.assertIsNone(runtime.bundled_path("fake"))

    def test_require_bundled_disables_host_fallback(self):
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {"ATOMIC_REQUIRE_BUNDLED_TOOLS": "1"}):
            with patch("core.tool_runtime.shutil.which", return_value="/usr/bin/fake"):
                runtime = ToolRuntime(td)
                self.assertIsNone(runtime.resolve("fake"))


if __name__ == "__main__":
    unittest.main()
