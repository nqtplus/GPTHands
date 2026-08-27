from __future__ import annotations

import os
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

    def test_unrelated_host_secrets_are_not_inherited(self) -> None:
        secret = "CONTROL_PLANE_ONLY_123"
        code = (
            "import os; "
            "print('github=' + os.environ.get('GITHUB_TOKEN', 'missing')); "
            "print('aws=' + os.environ.get('AWS_SECRET_ACCESS_KEY', 'missing')); "
            "print('openai=' + os.environ.get('OPENAI_API_KEY', 'missing')); "
            "print('control=' + os.environ.get('CONTROL_PLANE_API_KEY', 'missing'))"
        )
        poisoned = {
            "GITHUB_TOKEN": "github-parent-secret",
            "AWS_SECRET_ACCESS_KEY": "aws-parent-secret",
            "OPENAI_API_KEY": "openai-parent-secret",
            "CONTROL_PLANE_API_KEY": "stale-parent-control-secret",
        }
        with mock.patch.dict(os.environ, poisoned, clear=False):
            with mock.patch("gpthands.tunnel.CredentialStore.get", return_value=secret):
                completed = execute_tunnel_step(
                    [sys.executable, "-c", code],
                    credential_name="demo",
                    timeout=20,
                )
        self.assertEqual(completed.returncode, 0)
        self.assertIn("github=missing", completed.stdout)
        self.assertIn("aws=missing", completed.stdout)
        self.assertIn("openai=missing", completed.stdout)
        self.assertNotIn("github-parent-secret", completed.stdout)
        self.assertNotIn("aws-parent-secret", completed.stdout)
        self.assertNotIn("openai-parent-secret", completed.stdout)
        self.assertNotIn("stale-parent-control-secret", completed.stdout)
        self.assertIn("control=[REDACTED]", completed.stdout)

    def test_parent_control_plane_key_is_not_used_without_explicit_credential(self) -> None:
        code = "import os; print(os.environ.get('CONTROL_PLANE_API_KEY', 'missing'))"
        with mock.patch.dict(os.environ, {"CONTROL_PLANE_API_KEY": "ambient-secret"}, clear=False):
            completed = execute_tunnel_step([sys.executable, "-c", code], timeout=20)
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout.strip(), "missing")


if __name__ == "__main__":
    unittest.main()
