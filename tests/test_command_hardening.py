from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from gpthands.policy import Policy, PolicyError
from gpthands.risk import RiskLevel, classify_command, command_requires_network


class CommandHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name).resolve()
        self.workspace = self.base / "workspace"
        self.workspace.mkdir()
        self.policy_path = self.base / "policy.json"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def policy(self, *, network: bool = False) -> Policy:
        future = time.time() + 300
        data = {
            "schema_version": 3,
            "allow_process": True,
            "process_lease_until": future,
            "allow_network_commands": network,
            "network_lease_until": future if network else None,
            "allowed_commands": ["git"],
            "require_os_sandbox": False,
        }
        self.policy_path.write_text(json.dumps(data), encoding="utf-8")
        if os.name != "nt":
            os.chmod(self.policy_path, 0o600)
        return Policy.load(self.workspace, self.policy_path)

    def test_path_qualified_executable_cannot_impersonate_allowlisted_name(self) -> None:
        policy = self.policy()
        for program in ("./git", "tools/git", "../git"):
            with self.subTest(program=program):
                with self.assertRaisesRegex(PolicyError, "bare allowlisted name"):
                    policy.validate_command([program, "status"])

    def test_network_subcommand_hidden_behind_git_options_still_needs_lease(self) -> None:
        policy = self.policy(network=False)
        argv = ["git", "-c", "credential.helper=", "fetch"]
        self.assertTrue(command_requires_network(argv))
        with self.assertRaisesRegex(PolicyError, "network capability"):
            policy.validate_command(argv)

    def test_destructive_force_push_still_needs_network_lease(self) -> None:
        argv = ["git", "push", "--force-with-lease"]
        self.assertEqual(classify_command(argv), RiskLevel.DESTRUCTIVE)
        self.assertTrue(command_requires_network(argv))
        with self.assertRaisesRegex(PolicyError, "network capability"):
            self.policy(network=False).validate_command(argv)
        checked, risk = self.policy(network=True).validate_command(argv)
        self.assertEqual(checked, argv)
        self.assertEqual(risk, RiskLevel.DESTRUCTIVE)

    def test_windows_executable_suffixes_do_not_lower_risk(self) -> None:
        self.assertEqual(classify_command(["python.exe", "-c", "print(1)"]), RiskLevel.DESTRUCTIVE)
        self.assertEqual(classify_command(["cmd.exe", "/d", "/c", "echo ok"]), RiskLevel.DESTRUCTIVE)
        self.assertEqual(classify_command(["curl.exe", "https://example.invalid"]), RiskLevel.NETWORK)
        self.assertTrue(command_requires_network(["curl.exe", "https://example.invalid"]))


if __name__ == "__main__":
    unittest.main()
