from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from gpthands.approval import ApprovalError, ApprovalManager
from gpthands.audit import AuditLogger, content_fingerprint, redact_text
from gpthands.policy import Policy, PolicyError, default_policy_path
from gpthands.risk import RiskLevel, classify_command
from gpthands.sandbox import SandboxError, SandboxRunner
from gpthands.server import GPTHandsServer, _action_hash


class WorkspaceCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name).resolve()
        self.root = self.base / "workspace"
        self.root.mkdir()
        self.state = self.base / "state"
        self.state.mkdir()
        self.policy_path = self.state / "policy.json"
        self.audit_path = self.state / "audit.jsonl"
        self.key_path = self.state / "approval.key"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write_policy(self, **overrides) -> Path:
        future = time.time() + 1800
        data = {
            "allow_write": False,
            "allow_process": False,
            "allow_network_commands": False,
            "write_lease_until": None,
            "process_lease_until": None,
            "network_lease_until": None,
            "allowed_commands": [],
            "approval_required_from": "NETWORK",
            "require_os_sandbox": True,
        }
        data.update(overrides)
        self.policy_path.write_text(json.dumps(data), encoding="utf-8")
        if os.name != "nt":
            os.chmod(self.policy_path, 0o600)
        return self.policy_path

    def future_policy(self, **overrides) -> Path:
        future = time.time() + 1800
        values = {
            "allow_write": True,
            "allow_process": True,
            "write_lease_until": future,
            "process_lease_until": future,
            "allowed_commands": ["git", "python3", "curl"],
            "require_os_sandbox": False,
        }
        values.update(overrides)
        return self.write_policy(**values)

    def load(self) -> Policy:
        return Policy.load(self.root, self.policy_path)

    def server(self, *, sandbox=None) -> GPTHandsServer:
        audit = AuditLogger(self.audit_path, workspace=self.root)
        self.addCleanup(audit.close)
        approvals = ApprovalManager(self.key_path)
        return GPTHandsServer(self.load(), audit, approvals=approvals, sandbox=sandbox)

    @staticmethod
    def rpc(server: GPTHandsServer, name: str, arguments: dict | None = None) -> dict:
        response = server.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments or {}},
            }
        )
        assert response is not None
        return response["result"]


class PolicyV02Tests(WorkspaceCase):
    def test_default_policy_is_read_only_with_external_authority(self) -> None:
        policy = Policy.load(self.root, self.policy_path)
        self.assertFalse(policy.allow_write)
        self.assertFalse(policy.allow_process)
        self.assertFalse(policy.allow_network_commands)
        self.assertEqual(policy.policy_path, self.policy_path)

    def test_default_policy_path_is_outside_workspace(self) -> None:
        path = default_policy_path(self.root)
        self.assertFalse(str(path).startswith(str(self.root) + os.sep))

    def test_policy_inside_workspace_is_refused(self) -> None:
        bad = self.root / "policy.json"
        bad.write_text("{}", encoding="utf-8")
        with self.assertRaises(PolicyError):
            Policy.load(self.root, bad)

    def test_policy_must_be_mode_600(self) -> None:
        if os.name == "nt":
            self.skipTest("POSIX permission semantics")
        self.write_policy()
        os.chmod(self.policy_path, 0o644)
        with self.assertRaises(PolicyError):
            self.load()

    def test_mutable_capabilities_require_live_leases(self) -> None:
        self.write_policy(
            allow_write=True,
            allow_process=True,
            allow_network_commands=True,
            write_lease_until=time.time() - 1,
            process_lease_until=time.time() - 1,
            network_lease_until=time.time() - 1,
            allowed_commands=["git"],
        )
        expired = self.load()
        self.assertFalse(expired.allow_write)
        self.assertFalse(expired.allow_process)
        self.assertFalse(expired.allow_network_commands)

        future = time.time() + 300
        self.write_policy(
            allow_write=True,
            allow_process=True,
            allow_network_commands=True,
            write_lease_until=future,
            process_lease_until=future,
            network_lease_until=future,
            allowed_commands=["git"],
        )
        active = self.load()
        self.assertTrue(active.allow_write)
        self.assertTrue(active.allow_process)
        self.assertTrue(active.allow_network_commands)

    def test_path_escape_and_secret_paths_are_denied(self) -> None:
        policy = Policy.load(self.root, self.policy_path)
        for target in ["../outside", str(self.base / "outside"), ".env", "private.pem", ".gpthands.json"]:
            with self.subTest(target=target):
                with self.assertRaises(PolicyError):
                    policy.resolve_path(target)

    @unittest.skipIf(os.name == "nt", "symlink permissions vary on Windows")
    def test_symlink_escape_is_denied(self) -> None:
        outside = self.base / "outside.txt"
        outside.write_text("secret", encoding="utf-8")
        (self.root / "escape").symlink_to(outside)
        with self.assertRaises(PolicyError):
            Policy.load(self.root, self.policy_path).resolve_path("escape", must_exist=True)

    def test_command_risk_and_network_lease(self) -> None:
        future = time.time() + 300
        self.write_policy(
            allow_process=True,
            process_lease_until=future,
            allowed_commands=["git"],
        )
        policy = self.load()
        args, risk = policy.validate_command(["git", "status"])
        self.assertEqual(args, ["git", "status"])
        self.assertEqual(risk, RiskLevel.EXEC)
        with self.assertRaises(PolicyError):
            policy.validate_command(["git", "fetch"])

        self.write_policy(
            allow_process=True,
            allow_network_commands=True,
            process_lease_until=future,
            network_lease_until=future,
            allowed_commands=["git"],
        )
        _, network_risk = self.load().validate_command(["git", "fetch"])
        self.assertEqual(network_risk, RiskLevel.NETWORK)

    def test_destructive_classifier(self) -> None:
        self.assertEqual(classify_command(["git", "reset", "--hard"]), RiskLevel.DESTRUCTIVE)
        self.assertEqual(classify_command(["git", "push", "--force-with-lease"]), RiskLevel.DESTRUCTIVE)


class ApprovalTests(WorkspaceCase):
    def test_signed_token_is_workspace_and_risk_bound_and_one_time(self) -> None:
        manager = ApprovalManager(self.key_path)
        token = manager.issue(workspace=self.root, risk=RiskLevel.NETWORK, ttl_seconds=60, action_hash="abc")
        payload = manager.validate(token, workspace=self.root, minimum_risk=RiskLevel.NETWORK, action_hash="abc")
        self.assertEqual(payload["risk"], "NETWORK")
        with self.assertRaises(ApprovalError):
            manager.validate(token, workspace=self.root, minimum_risk=RiskLevel.NETWORK, action_hash="abc")

    def test_token_rejects_wrong_workspace_or_action(self) -> None:
        manager = ApprovalManager(self.key_path)
        token = manager.issue(workspace=self.root, risk=RiskLevel.DESTRUCTIVE, ttl_seconds=60, action_hash="abc")
        other = self.base / "other"
        other.mkdir()
        with self.assertRaises(ApprovalError):
            manager.validate(token, workspace=other, minimum_risk=RiskLevel.WRITE, action_hash="abc", consume=False)
        with self.assertRaises(ApprovalError):
            manager.validate(token, workspace=self.root, minimum_risk=RiskLevel.WRITE, action_hash="different", consume=False)

    def test_unbound_token_cannot_authorize_an_exact_action(self) -> None:
        manager = ApprovalManager(self.key_path)
        token = manager.issue(workspace=self.root, risk=RiskLevel.DESTRUCTIVE, ttl_seconds=60)
        with self.assertRaisesRegex(ApprovalError, "exact action"):
            manager.validate(
                token,
                workspace=self.root,
                minimum_risk=RiskLevel.WRITE,
                action_hash="abc",
                consume=False,
            )

    def test_key_permissions_are_600(self) -> None:
        ApprovalManager(self.key_path)
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(self.key_path.stat().st_mode), 0o600)


class SandboxPlanningTests(WorkspaceCase):
    def test_linux_bwrap_denies_network_and_mounts_workspace_read_only(self) -> None:
        runner = SandboxRunner(require_os_sandbox=True)
        with patch("gpthands.sandbox.platform.system", return_value="Linux"), patch("gpthands.sandbox.shutil.which", return_value="/usr/bin/bwrap"):
            plan = runner.plan(
                command=["git", "status"],
                workspace=self.root,
                cwd=self.root,
                allow_write=False,
                allow_network=False,
                isolated_home=self.state,
            )
        self.assertEqual(plan.backend, "bubblewrap")
        self.assertIn("--unshare-all", plan.argv)
        self.assertNotIn("--share-net", plan.argv)
        joined = " ".join(plan.argv)
        self.assertIn(f"--ro-bind {self.root} {self.root}", joined)

    def test_linux_network_and_write_are_explicit(self) -> None:
        runner = SandboxRunner(require_os_sandbox=True)
        with patch("gpthands.sandbox.platform.system", return_value="Linux"), patch("gpthands.sandbox.shutil.which", return_value="/usr/bin/bwrap"):
            plan = runner.plan(
                command=["git", "fetch"],
                workspace=self.root,
                cwd=self.root,
                allow_write=True,
                allow_network=True,
                isolated_home=self.state,
            )
        self.assertIn("--share-net", plan.argv)
        self.assertIn(f"--bind {self.root} {self.root}", " ".join(plan.argv))

    def test_macos_profile_denies_network_by_default(self) -> None:
        runner = SandboxRunner(require_os_sandbox=True)
        with patch("gpthands.sandbox.platform.system", return_value="Darwin"), patch("gpthands.sandbox.shutil.which", return_value="/usr/bin/sandbox-exec"):
            plan = runner.plan(
                command=["git", "status"],
                workspace=self.root,
                cwd=self.root,
                allow_write=False,
                allow_network=False,
                isolated_home=self.state,
            )
        self.assertEqual(plan.backend, "sandbox-exec")
        self.assertIsNotNone(plan.profile_text)
        self.assertNotIn("network-outbound", plan.profile_text or "")
        self.assertNotIn(f"file-write* (subpath \"{self.root}\")", plan.profile_text or "")

    def test_required_sandbox_refuses_missing_backend(self) -> None:
        runner = SandboxRunner(require_os_sandbox=True)
        with patch("gpthands.sandbox.platform.system", return_value="Linux"), patch("gpthands.sandbox.shutil.which", return_value=None):
            with self.assertRaises(SandboxError):
                runner.plan(
                    command=["git", "status"],
                    workspace=self.root,
                    cwd=self.root,
                    allow_write=False,
                    allow_network=False,
                    isolated_home=self.state,
                )


class FakeSandbox:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def run(self, **kwargs):
        self.calls.append(kwargs)
        command = kwargs["command"]
        output = ("fake:" + " ".join(command)).encode("utf-8")
        return subprocess.CompletedProcess(command, 0, stdout=output), "fake-sandbox"


class ServerV02Tests(WorkspaceCase):
    def test_tools_list_contains_v02_tools(self) -> None:
        self.write_policy()
        server = self.server(sandbox=FakeSandbox())
        response = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        assert response is not None
        names = {tool["name"] for tool in response["result"]["tools"]}
        self.assertTrue({"preview_edit", "apply_edit", "git_status", "git_diff", "run_command"}.issubset(names))

    def test_write_is_denied_without_live_lease(self) -> None:
        self.write_policy(allow_write=True, write_lease_until=time.time() - 1)
        result = self.rpc(self.server(sandbox=FakeSandbox()), "write_file", {"target": "x.txt", "content": "x"})
        self.assertTrue(result["isError"])
        self.assertFalse((self.root / "x.txt").exists())

    def test_preview_then_apply_is_one_time_and_checks_base_hash(self) -> None:
        self.future_policy()
        (self.root / "a.txt").write_text("old\n", encoding="utf-8")
        server = self.server(sandbox=FakeSandbox())
        preview = self.rpc(server, "preview_edit", {"target": "a.txt", "new_content": "new\n"})
        self.assertFalse(preview["isError"])
        payload = json.loads(preview["content"][0]["text"])
        applied = self.rpc(
            server,
            "apply_edit",
            {
                "target": "a.txt",
                "new_content": "new\n",
                "base_sha256": payload["base_sha256"],
                "preview_id": payload["preview_id"],
            },
        )
        self.assertFalse(applied["isError"])
        self.assertEqual((self.root / "a.txt").read_text(encoding="utf-8"), "new\n")
        replay = self.rpc(
            server,
            "apply_edit",
            {
                "target": "a.txt",
                "new_content": "new\n",
                "base_sha256": payload["base_sha256"],
                "preview_id": payload["preview_id"],
            },
        )
        self.assertTrue(replay["isError"])

    def test_overwrite_requires_human_approval_by_default_threshold(self) -> None:
        self.future_policy(approval_required_from="DESTRUCTIVE")
        (self.root / "x.txt").write_text("old", encoding="utf-8")
        server = self.server(sandbox=FakeSandbox())
        denied = self.rpc(server, "write_file", {"target": "x.txt", "content": "new", "overwrite": True})
        self.assertTrue(denied["isError"])
        action_hash = _action_hash(
            "write_file",
            {"target": "x.txt", "overwrite": True, "content": content_fingerprint("new")},
        )
        token = server.approvals.issue(
            workspace=self.root,
            risk=RiskLevel.DESTRUCTIVE,
            ttl_seconds=60,
            action_hash=action_hash,
        )
        allowed = self.rpc(server, "write_file", {"target": "x.txt", "content": "new", "overwrite": True, "approval_token": token})
        self.assertFalse(allowed["isError"])
        self.assertEqual((self.root / "x.txt").read_text(encoding="utf-8"), "new")

    def test_exec_uses_sandbox_and_readonly_workspace_when_write_lease_off(self) -> None:
        future = time.time() + 300
        self.write_policy(
            allow_process=True,
            process_lease_until=future,
            allowed_commands=["git"],
            require_os_sandbox=True,
        )
        fake = FakeSandbox()
        result = self.rpc(self.server(sandbox=fake), "run_command", {"argv": ["git", "status"]})
        self.assertFalse(result["isError"])
        self.assertFalse(fake.calls[0]["allow_write"])
        self.assertFalse(fake.calls[0]["allow_network"])

    def test_network_command_needs_network_lease_and_approval(self) -> None:
        future = time.time() + 300
        self.write_policy(
            allow_process=True,
            allow_network_commands=True,
            process_lease_until=future,
            network_lease_until=future,
            allowed_commands=["git"],
            approval_required_from="NETWORK",
            require_os_sandbox=True,
        )
        fake = FakeSandbox()
        server = self.server(sandbox=fake)
        denied = self.rpc(server, "run_command", {"argv": ["git", "fetch"]})
        self.assertTrue(denied["isError"])
        action_hash = _action_hash("run_command", {"argv": ["git", "fetch"], "cwd": "."})
        token = server.approvals.issue(
            workspace=self.root,
            risk=RiskLevel.NETWORK,
            ttl_seconds=60,
            action_hash=action_hash,
        )
        allowed = self.rpc(server, "run_command", {"argv": ["git", "fetch"], "approval_token": token})
        self.assertFalse(allowed["isError"])
        self.assertTrue(fake.calls[-1]["allow_network"])

    def test_curated_git_tools_are_read_only_and_do_not_need_process_lease(self) -> None:
        self.write_policy(require_os_sandbox=True)
        fake = FakeSandbox()
        server = self.server(sandbox=fake)
        result = self.rpc(server, "git_status")
        self.assertFalse(result["isError"])
        self.assertEqual(fake.calls[0]["command"][:2], ["git", "status"])
        self.assertFalse(fake.calls[0]["allow_write"])
        self.assertFalse(fake.calls[0]["allow_network"])

    def test_audit_does_not_store_file_content_or_token(self) -> None:
        self.future_policy(approval_required_from="DESTRUCTIVE")
        server = self.server(sandbox=FakeSandbox())
        secret = "sk-abcdefghijklmnopqrstuv"
        result = self.rpc(server, "write_file", {"target": "created.txt", "content": secret})
        self.assertFalse(result["isError"])
        audit = self.audit_path.read_text(encoding="utf-8")
        self.assertNotIn(secret, audit)
        self.assertIn("sha256", audit)


class RedactionTests(unittest.TestCase):
    def test_common_secret_formats_are_redacted(self) -> None:
        text = "x sk-abcdefghijklmnopqrstuv y ghp_abcdefghijklmnopqrstuvwxyz123456 z"
        redacted = redact_text(text)
        self.assertNotIn("sk-abcdefghijklmnopqrstuv", redacted)
        self.assertNotIn("ghp_abcdefghijklmnopqrstuvwxyz123456", redacted)


if __name__ == "__main__":
    unittest.main()
