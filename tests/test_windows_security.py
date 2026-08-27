from __future__ import annotations

import os
import platform
import tempfile
import unittest
from pathlib import Path

from gpthands.sandbox import SandboxRunner
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

    def run_sandbox(self, command: list[str], *, allow_write: bool = False, allow_network: bool = False):
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

    def test_backend_is_real_appcontainer_and_captures_output(self) -> None:
        completed, backend = self.run_sandbox(["cmd.exe", "/d", "/c", "echo GPTHANDS_APPCONTAINER_OK"])
        self.assertTrue(backend.startswith("windows-appcontainer"), backend)
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
            [
                "curl.exe",
                "--connect-timeout", "2",
                "--max-time", "3",
                "--silent",
                "--show-error",
                "--head",
                "https://1.1.1.1/",
            ],
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


if __name__ == "__main__":
    unittest.main()
