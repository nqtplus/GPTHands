from __future__ import annotations

import os
import platform
import sys
import tempfile
import unittest
from pathlib import Path

from gpthands.sandbox import SandboxRunner
from gpthands.windows_sandbox import WindowsAppContainerSandbox, build_sandbox_spec


class WindowsSpecTests(unittest.TestCase):
    def test_flatbuffer_has_sbox_identifier_and_workspace_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            blob = build_sandbox_spec(read_write=[root], read_only=[root / "read"], allow_network=False)
            self.assertEqual(blob[4:8], b"SBOX")
            self.assertIn("0.1.0".encode(), blob)
            self.assertIn(str(root).encode(), blob)
            self.assertNotIn(b"internetClient", blob)


@unittest.skipUnless(platform.system() == "Windows", "Windows-only AppContainer integration")
class WindowsAppContainerIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        if not WindowsAppContainerSandbox.available():
            self.fail("processmodel.dll Experimental_CreateProcessInSandbox is unavailable; Windows AppContainer isolation must not silently skip")
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name).resolve()
        self.workspace = self.base / "workspace"
        self.workspace.mkdir()
        self.outside = self.base / "outside-secret.txt"
        self.outside.write_text("HOST_SECRET_SENTINEL", encoding="utf-8")
        self.runner = SandboxRunner(require_os_sandbox=True)
        self.env = {
            "PATH": os.environ.get("PATH", ""),
            "NO_COLOR": "1",
        }

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
        self.assertEqual(backend, "windows-appcontainer")
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

    def test_workspace_write_is_denied_then_explicitly_allowed(self) -> None:
        target = self.workspace / "created.txt"
        completed, _ = self.run_sandbox(
            ["cmd.exe", "/d", "/c", f"echo BLOCKED>{target}"],
            allow_write=False,
        )
        self.assertFalse(target.exists(), completed.stdout.decode(errors="replace"))

        completed, _ = self.run_sandbox(
            ["cmd.exe", "/d", "/c", f"echo ALLOWED>{target}"],
            allow_write=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout.decode(errors="replace"))
        self.assertTrue(target.exists())
        self.assertIn("ALLOWED", target.read_text(encoding="utf-8"))

    def test_network_is_denied_without_capability(self) -> None:
        code = (
            "import socket,sys; "
            "s=socket.socket(); s.settimeout(2); "
            "\ntry: s.connect(('1.1.1.1',443))\n"
            "except OSError: sys.exit(0)\n"
            "else: sys.exit(9)"
        )
        completed, _ = self.run_sandbox([sys.executable, "-c", code], allow_network=False)
        self.assertEqual(completed.returncode, 0, "network connection unexpectedly escaped AppContainer isolation")


if __name__ == "__main__":
    unittest.main()
