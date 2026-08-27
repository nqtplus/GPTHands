from __future__ import annotations

import os
import platform
import sys
import tempfile
import time
import unittest
from pathlib import Path

from gpthands.process_control import run_bounded_process


@unittest.skipIf(platform.system() == "Windows", "secure Windows execution uses AppContainer + Job Object")
class BoundedProcessOutputTests(unittest.TestCase):
    def test_large_stdout_is_streamed_with_bounded_retention(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = run_bounded_process(
                [sys.executable, "-c", "import sys; sys.stdout.write('X' * (4 * 1024 * 1024))"],
                cwd=Path(tmp),
                env=dict(os.environ),
                timeout=10,
                max_output_bytes=8192,
            )
        marker = b"\n[output truncated by GPTHands policy]"
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.stdout.startswith(b"X" * 128))
        self.assertTrue(result.stdout.endswith(marker))
        self.assertEqual(len(result.stdout), 8192 + len(marker))

    def test_background_descendant_cannot_keep_action_pipe_alive(self) -> None:
        child = "import time; time.sleep(30)"
        parent = (
            "import subprocess, sys; "
            f"subprocess.Popen([sys.executable, '-c', {child!r}]); "
            "print('ROOT_DONE', flush=True)"
        )
        started = time.monotonic()
        with tempfile.TemporaryDirectory() as tmp:
            result = run_bounded_process(
                [sys.executable, "-c", parent],
                cwd=Path(tmp),
                env=dict(os.environ),
                timeout=10,
                max_output_bytes=8192,
            )
        elapsed = time.monotonic() - started
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"ROOT_DONE", result.stdout)
        self.assertLess(elapsed, 8, "inherited stdout from a background descendant kept the action alive")


if __name__ == "__main__":
    unittest.main()
