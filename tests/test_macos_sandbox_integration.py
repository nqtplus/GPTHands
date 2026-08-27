from __future__ import annotations

import platform
import shutil
import tempfile
import unittest
from pathlib import Path

from gpthands.sandbox import SandboxRunner


@unittest.skipUnless(platform.system() == "Darwin" and shutil.which("sandbox-exec"), "macOS sandbox integration requires sandbox-exec")
class MacOSSandboxIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self.tmp.name).resolve()
        self.runner = SandboxRunner(require_os_sandbox=True)
        self.env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "NO_COLOR": "1"}

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_box(self, command: list[str], *, allow_write: bool = False, allow_network: bool = False):
        return self.runner.run(
            command=command,
            workspace=self.workspace,
            cwd=self.workspace,
            allow_write=allow_write,
            allow_network=allow_network,
            env=self.env,
            timeout=10,
            max_output_bytes=100_000,
        )

    def test_workspace_read_succeeds(self) -> None:
        target = self.workspace / "read.txt"
        target.write_text("hello", encoding="utf-8")
        completed, backend = self.run_box(["/bin/cat", str(target)])
        self.assertEqual(backend, "sandbox-exec")
        self.assertEqual(completed.returncode, 0, completed.stdout.decode("utf-8", errors="replace"))
        self.assertEqual(completed.stdout.decode("utf-8"), "hello")

    def test_workspace_write_is_denied_without_write_capability(self) -> None:
        target = self.workspace / "blocked.txt"
        completed, backend = self.run_box(["/bin/sh", "-c", f"printf x > '{target}'"], allow_write=False)
        self.assertEqual(backend, "sandbox-exec")
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse(target.exists())

    def test_workspace_write_is_allowed_when_explicit(self) -> None:
        target = self.workspace / "allowed.txt"
        completed, backend = self.run_box(["/bin/sh", "-c", f"printf x > '{target}'"], allow_write=True)
        self.assertEqual(backend, "sandbox-exec")
        self.assertEqual(completed.returncode, 0, completed.stdout.decode("utf-8", errors="replace"))
        self.assertEqual(target.read_text(encoding="utf-8"), "x")


if __name__ == "__main__":
    unittest.main()
