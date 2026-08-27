from __future__ import annotations

import platform
import tempfile
import unittest
from pathlib import Path

from gpthands.sandbox import SandboxError, SandboxRunner


@unittest.skipUnless(platform.system() == "Windows", "Windows-only security behavior")
class WindowsSecurityTests(unittest.TestCase):
    def test_required_os_sandbox_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp).resolve()
            runner = SandboxRunner(require_os_sandbox=True)
            with self.assertRaises(SandboxError):
                runner.plan(
                    command=["cmd.exe", "/c", "echo", "blocked"],
                    workspace=workspace,
                    cwd=workspace,
                    allow_write=False,
                    allow_network=False,
                    isolated_home=workspace,
                )


if __name__ == "__main__":
    unittest.main()
