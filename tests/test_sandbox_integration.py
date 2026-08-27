from __future__ import annotations

import platform
import shutil
import tempfile
import unittest
from pathlib import Path

from gpthands.sandbox import SandboxError, SandboxRunner


@unittest.skipUnless(platform.system() == "Linux" and shutil.which("bwrap"), "bubblewrap integration requires Linux + bwrap")
class BubblewrapIntegrationTests(unittest.TestCase):
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

    def test_readonly_workspace_rejects_write(self) -> None:
        # Share host networking for this test so it isolates the filesystem
        # behavior from kernels that disallow unprivileged network namespaces.
        target = self.workspace / "blocked.txt"
        completed, backend = self.run_box(
            ["/bin/sh", "-c", f"printf x > '{target}'"],
            allow_write=False,
            allow_network=True,
        )
        self.assertEqual(backend, "bubblewrap")
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse(target.exists())

    def test_write_mount_is_explicit(self) -> None:
        target = self.workspace / "allowed.txt"
        completed, backend = self.run_box(
            ["/bin/sh", "-c", f"printf x > '{target}'"],
            allow_write=True,
            allow_network=True,
        )
        self.assertEqual(backend, "bubblewrap")
        self.assertEqual(completed.returncode, 0, completed.stdout.decode("utf-8", errors="replace"))
        self.assertEqual(target.read_text(encoding="utf-8"), "x")

    def test_network_denial_is_isolated_or_fails_closed(self) -> None:
        marker = self.workspace / "target-ran.txt"
        command = [
            "/bin/sh",
            "-c",
            f"printf ran > '{marker}'; /bin/cat /proc/net/route",
        ]
        try:
            completed, backend = self.run_box(
                command,
                allow_write=True,
                allow_network=False,
            )
        except SandboxError as exc:
            # Some hosted kernels forbid unprivileged network namespace setup.
            # Secure behavior is to refuse the target rather than silently share
            # host networking.
            self.assertIn("network namespace isolation is unavailable", str(exc))
            self.assertFalse(marker.exists(), "target command must not run when netns setup fails")
            return

        self.assertEqual(backend, "bubblewrap")
        self.assertEqual(completed.returncode, 0, completed.stdout.decode("utf-8", errors="replace"))
        self.assertEqual(marker.read_text(encoding="utf-8"), "ran")
        lines = [line for line in completed.stdout.decode("utf-8", errors="replace").splitlines() if line.strip()]
        self.assertLessEqual(len(lines), 1, completed.stdout.decode("utf-8", errors="replace"))


if __name__ == "__main__":
    unittest.main()
