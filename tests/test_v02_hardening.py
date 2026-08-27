from __future__ import annotations

import json
import os
import stat
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from gpthands.approval import ApprovalError, ApprovalManager
from gpthands.cli import main as cli_main
from gpthands.policy import Policy, PolicyError, default_policy_path
from gpthands.risk import RiskLevel, classify_command


class V02HardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name).resolve()
        self.workspace = self.base / "workspace"
        self.workspace.mkdir()
        self.state = self.base / "state"
        self.state.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_interpreters_and_shells_are_destructive(self) -> None:
        for command in (["python3", "-c", "print(1)"], ["node", "x.js"], ["bash", "-c", "echo hi"]):
            with self.subTest(command=command):
                self.assertEqual(classify_command(command), RiskLevel.DESTRUCTIVE)

    def test_live_lease_expires_without_server_restart(self) -> None:
        now = time.time()
        policy = Policy(
            workspace=self.workspace,
            policy_path=self.state / "policy.json",
            write_enabled=True,
            process_enabled=True,
            network_enabled=True,
            write_lease_until=now + 10,
            process_lease_until=now + 10,
            network_lease_until=now + 10,
        )
        with patch("gpthands.policy.time.time", return_value=now + 1):
            self.assertTrue(policy.allow_write)
            self.assertTrue(policy.allow_process)
            self.assertTrue(policy.allow_network_commands)
        with patch("gpthands.policy.time.time", return_value=now + 11):
            self.assertFalse(policy.allow_write)
            self.assertFalse(policy.allow_process)
            self.assertFalse(policy.allow_network_commands)

    def test_approval_replay_is_rejected_after_manager_restart(self) -> None:
        key = self.state / "approval.key"
        used = self.state / "used.jsonl"
        first = ApprovalManager(key, used)
        token = first.issue(workspace=self.workspace, risk=RiskLevel.EXEC, ttl_seconds=60)
        first.validate(token, workspace=self.workspace, minimum_risk=RiskLevel.EXEC)
        second = ApprovalManager(key, used)
        with self.assertRaises(ApprovalError):
            second.validate(token, workspace=self.workspace, minimum_risk=RiskLevel.EXEC)

    @unittest.skipIf(os.name == "nt", "symlink semantics differ on Windows")
    def test_policy_symlink_is_rejected_before_resolution(self) -> None:
        real = self.state / "real.json"
        real.write_text("{}", encoding="utf-8")
        os.chmod(real, 0o600)
        link = self.state / "policy.json"
        link.symlink_to(real)
        with self.assertRaises(PolicyError):
            Policy.load(self.workspace, link)

    def test_policy_cannot_grant_more_than_24_hours(self) -> None:
        path = self.state / "policy.json"
        path.write_text(
            json.dumps({"allow_write": True, "write_lease_until": time.time() + 90_000}),
            encoding="utf-8",
        )
        if os.name != "nt":
            os.chmod(path, 0o600)
        with self.assertRaises(PolicyError):
            Policy.load(self.workspace, path)

    def test_cli_init_policy_writes_external_mode_600(self) -> None:
        config_home = self.base / "config"
        with patch.dict(os.environ, {"XDG_CONFIG_HOME": str(config_home)}, clear=False):
            rc = cli_main([
                "init-policy",
                "--workspace",
                str(self.workspace),
                "--lease-seconds",
                "300",
                "--allow-write",
                "--allow-process",
                "--command",
                "git",
            ])
            self.assertEqual(rc, 0)
            path = default_policy_path(self.workspace)
            self.assertTrue(path.exists())
            self.assertFalse(str(path).startswith(str(self.workspace) + os.sep))
            loaded = Policy.load(self.workspace, path)
            self.assertTrue(loaded.allow_write)
            self.assertTrue(loaded.allow_process)
            self.assertFalse(loaded.allow_network_commands)
            self.assertEqual(loaded.approval_required_from, RiskLevel.EXEC)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
