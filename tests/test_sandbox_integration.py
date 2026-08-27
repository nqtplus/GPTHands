from __future__ import annotations

import os
import platform
import shutil
import tempfile
import unittest
from pathlib import Path

from gpthands.sandbox import SandboxError, SandboxRunner


_STRICT_BWRAP = os.environ.get("GPTHANDS_BWRAP_STRICT") == "1"


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

    def fail_closed_or_raise(self, exc: SandboxError, *, marker: Path | None = None) -> None:
        if _STRICT_BWRAP:
            self.fail(f"bubblewrap must be functional in strict integration mode: {exc}")
        self.assertIn("bubblewrap sandbox setup failed", str(exc))
        if marker is not None:
            self.assertFalse(marker.exists(), "target command must not run when sandbox setup fails")

    def test_readonly_workspace_rejects_write(self) -> None:
        # Share host networking here so this test isolates filesystem behavior.
        # A hosted kernel may still deny user namespaces entirely; non-strict
        # mode then verifies fail-closed/no side effect, while the privileged CI
        # pass below verifies the actual mount enforcement path.
        target = self.workspace / "blocked.txt"
        try:
            completed, backend = self.run_box(
                ["/bin/sh", "-c", f"printf x > '{target}'"],
                allow_write=False,
                allow_network=True,
            )
        except SandboxError as exc:
            self.fail_closed_or_raise(exc, marker=target)
            return

        self.assertEqual(backend, "bubblewrap")
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse(target.exists())

    def test_write_mount_is_explicit(self) -> None:
        target = self.workspace / "allowed.txt"
        try:
            completed, backend = self.run_box(
                ["/bin/sh", "-c", f"printf x > '{target}'"],
                allow_write=True,
                allow_network=True,
            )
        except SandboxError as exc:
            self.fail_closed_or_raise(exc, marker=target)
            return

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
            if _STRICT_BWRAP:
                self.fail(f"network namespace must be functional in strict integration mode: {exc}")
            # Some hosted kernels forbid unprivileged user/network namespace
            # setup. Secure behavior is refusal before the target runs.
            self.assertTrue(
                "network namespace isolation is unavailable" in str(exc)
                or "bubblewrap sandbox setup failed" in str(exc)
            )
            self.assertFalse(marker.exists(), "target command must not run when namespace setup fails")
            return

        self.assertEqual(backend, "bubblewrap")
        self.assertEqual(completed.returncode, 0, completed.stdout.decode("utf-8", errors="replace"))
        self.assertEqual(marker.read_text(encoding="utf-8"), "ran")
        lines = [line for line in completed.stdout.decode("utf-8", errors="replace").splitlines() if line.strip()]
        self.assertLessEqual(len(lines), 1, completed.stdout.decode("utf-8", errors="replace"))


if __name__ == "__main__":
    unittest.main()
