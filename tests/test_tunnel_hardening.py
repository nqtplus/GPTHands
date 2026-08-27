from __future__ import annotations

import sys
import unittest
from unittest import mock

from gpthands.tunnel import execute_tunnel_step


class TunnelHardeningTests(unittest.TestCase):
    def test_secret_echo_is_redacted_and_output_is_bounded(self) -> None:
        secret = "CONTROL_PLANE_SECRET_SENTINEL_123456789"
        code = (
            "import os, sys; "
            "print(os.environ.get('CONTROL_PLANE_API_KEY', 'missing'), flush=True); "
            "sys.stdout.write('X' * 1500000)"
        )
        with mock.patch("gpthands.tunnel.CredentialStore.get", return_value=secret):
            completed = execute_tunnel_step(
                [sys.executable, "-c", code],
                credential_name="demo",
                timeout=20,
            )
        self.assertEqual(completed.returncode, 0)
        self.assertNotIn(secret, completed.stdout)
        self.assertIn("[REDACTED]", completed.stdout)
        self.assertIn("[output truncated by GPTHands tunnel policy]", completed.stdout)
        self.assertLess(len(completed.stdout.encode("utf-8")), 1_100_000)


if __name__ == "__main__":
    unittest.main()
