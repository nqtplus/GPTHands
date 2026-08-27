from __future__ import annotations

import os
import platform
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from gpthands.sandbox import SandboxError, SandboxRunner
from gpthands.windows_classic import WindowsAppContainerSandbox
from gpthands.windows_sandbox import build_sandbox_spec


class WindowsSpecTests(unittest.TestCase):
    def test_flatbuffer_has_sbox_identifier_and_workspace_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            blob = build_sandbox_spec(read_write=[root], read_only=[root / "read"], allow_network=False)
            self.assertEqual(blob[4:8], b"SBOX")
            self.assertIn(b"0.1.0", blob)
            self.assertIn(str(root).encode(), blob)
            self.assertNotIn(b"internetClient", blob)


@unittest.skipUnless(platform.system() == "Windows", "Windows-only AppContainer integration")
class WindowsAppContainerIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        if not WindowsAppContainerSandbox.available():
            self.fail("no native Windows AppContainer backend is available; isolation must not silently skip")
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name).resolve()
        self.workspace = self.base / "workspace"
        self.workspace.mkdir()
        self.outside = self.base / "outside-secret.txt"
        self.outside.write_text("HOST_SECRET_SENTINEL", encoding="utf-8")
        self.runner = SandboxRunner(require_os_sandbox=True)
        self.env = {"PATH": os.environ.get("PATH", ""), "NO_COLOR": "1"}

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_sandbox(self, command: list[str], *, allow_write: bool = False, allow_network: bool = False, timeout: int = 10):
        return self.runner.run(
            command=command,
            workspace=self.workspace,
            cwd=self.workspace,
            allow_write=allow_write,
            allow_network=allow_network,
            env=self.env,
            timeout=timeout,
            max_output_bytes=100_000,
        )

    def test_backend_is_real_appcontainer_job_and_captures_output(self) -> None:
        completed, backend = self.run_sandbox(["cmd.exe", "/d", "/c", "echo GPTHANDS_APPCONTAINER_OK"])
        self.assertEqual(backend, "windows-appcontainer-classic-job", backend)
        self.assertEqual(completed.returncode, 0, completed.stdout.decode(errors="replace"))
        self.assertIn(b"GPTHANDS_APPCONTAINER_OK", completed.stdout)

    def test_workspace_read_allowed_but_outside_read_denied(self) -> None:
        inside = self.workspace / "inside.txt"
        inside.write_text("WORKSPACE_SENTINEL", encoding="utf-8")
        completed, _ = self.run_sandbox(["cmd.exe", "/d", "/c", "type", str(inside)])
        self.assertEqual(completed.returncode, 0, completed.stdout.decode(errors="replace"))
        self.assertIn(b"WORKSPACE_SENTINEL", completed.stdout)

        completed, _ = self.run_sandbox(["cmd.exe", "/d", "/c", "type", str(self.outside)])
        self.assertNotEqual(completed.returncode, 0)
        self.assertNotIn(b"HOST_SECRET_SENTINEL", completed.stdout)

    def test_workspace_acl_is_read_only_then_explicitly_read_write(self) -> None:
        target = self.workspace / "created.txt"
        command = ["cmd.exe", "/d", "/c", "echo ALLOWED>created.txt"]

        completed, _ = self.run_sandbox(command, allow_write=False)
        self.assertNotEqual(completed.returncode, 0, "read-only AppContainer staging unexpectedly accepted a write")
        self.assertFalse(target.exists())

        completed, _ = self.run_sandbox(command, allow_write=True)
        self.assertEqual(completed.returncode, 0, completed.stdout.decode(errors="replace"))
        self.assertTrue(target.exists())
        self.assertIn("ALLOWED", target.read_text(encoding="utf-8"))

    def test_network_is_denied_without_capability(self) -> None:
        completed, _ = self.run_sandbox(
            ["curl.exe", "--connect-timeout", "2", "--max-time", "3", "--silent", "--show-error", "--head", "https://1.1.1.1/"],
            allow_network=False,
        )
        self.assertNotEqual(completed.returncode, 0, "outbound network unexpectedly escaped AppContainer isolation")

    def test_arbitrary_host_environment_is_not_inherited(self) -> None:
        secret_name = "GPTHANDS_HOST_SECRET_SENTINEL"
        old = os.environ.get(secret_name)
        os.environ[secret_name] = "SHOULD_NOT_LEAK_9471"
        try:
            completed, _ = self.run_sandbox(["cmd.exe", "/d", "/c", f"set {secret_name}"])
        finally:
            if old is None:
                os.environ.pop(secret_name, None)
            else:
                os.environ[secret_name] = old
        self.assertNotIn(b"SHOULD_NOT_LEAK_9471", completed.stdout)

    def test_job_object_kills_descendant_after_root_exits(self) -> None:
        marker = self.workspace / "child-leak.txt"
        child = 'Start-Sleep -Seconds 3; Set-Content -LiteralPath child-leak.txt -Value LEAK'
        command = ["cmd.exe", "/d", "/c", f'start "" /b powershell.exe -NoProfile -NonInteractive -Command "{child}"']
        completed, backend = self.run_sandbox(command, allow_write=True)
        self.assertEqual(backend, "windows-appcontainer-classic-job")
        self.assertEqual(completed.returncode, 0, completed.stdout.decode(errors="replace"))
        time.sleep(4)
        self.assertFalse(marker.exists(), "descendant escaped Job Object cleanup after root exit")

    def test_timeout_terminates_job_process_tree(self) -> None:
        marker = self.workspace / "timeout-child-leak.txt"
        child = 'Start-Sleep -Seconds 3; Set-Content -LiteralPath timeout-child-leak.txt -Value LEAK'
        command = [
            "cmd.exe", "/d", "/c",
            f'start "" /b powershell.exe -NoProfile -NonInteractive -Command "{child}" & ping 127.0.0.1 -n 30 >nul',
        ]
        with self.assertRaises(SandboxError):
            self.run_sandbox(command, allow_write=True, timeout=1)
        time.sleep(4)
        self.assertFalse(marker.exists(), "descendant survived Job Object timeout termination")

    def test_workspace_junction_escape_is_refused_before_execution(self) -> None:
        outside_dir = self.base / "outside-dir"
        outside_dir.mkdir()
        (outside_dir / "secret.txt").write_text("JUNCTION_SECRET", encoding="utf-8")
        junction = self.workspace / "escape"
        created = subprocess.run(
            ["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(outside_dir)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        if created.returncode != 0:
            self.skipTest(f"runner cannot create junction: {created.stdout.decode(errors='replace')}")
        with self.assertRaises(SandboxError):
            self.run_sandbox(["cmd.exe", "/d", "/c", "echo SHOULD_NOT_RUN"])


if __name__ == "__main__":
    unittest.main()
