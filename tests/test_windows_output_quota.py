from __future__ import annotations

import os
import platform
import tempfile
import unittest
from pathlib import Path

from gpthands.sandbox import SandboxError, SandboxRunner
from gpthands.windows_classic import WindowsAppContainerSandbox


@unittest.skipUnless(platform.system() == "Windows", "Windows-only AppContainer output quota integration")
class WindowsOutputQuotaIntegrationTests(unittest.TestCase):
    def test_output_quota_terminates_job_during_execution(self) -> None:
        if not WindowsAppContainerSandbox.available():
            self.fail("no native Windows AppContainer backend is available")
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp).resolve() / "workspace"
            workspace.mkdir()
            runner = SandboxRunner(require_os_sandbox=True)
            env = {"PATH": os.environ.get("PATH", ""), "NO_COLOR": "1"}
            command = [
                "cmd.exe",
                "/d",
                "/c",
                "for /L %i in (1,1,50000) do @echo 1234567890",
            ]
            with self.assertRaisesRegex(SandboxError, "output limit"):
                runner.run(
                    command=command,
                    workspace=workspace,
                    cwd=workspace,
                    allow_write=False,
                    allow_network=False,
                    env=env,
                    timeout=10,
                    max_output_bytes=4096,
                )


if __name__ == "__main__":
    unittest.main()
