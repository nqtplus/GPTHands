from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from gpthands.audit import AuditLogger, redact_text
from gpthands.policy import Policy, PolicyError
from gpthands.server import GPTHandsServer


class PolicySecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write_policy(self, value: dict) -> None:
        (self.root / ".gpthands.json").write_text(json.dumps(value), encoding="utf-8")

    def test_default_is_read_only_and_no_process(self) -> None:
        policy = Policy.load(self.root)
        self.assertFalse(policy.allow_write)
        self.assertFalse(policy.allow_process)
        with self.assertRaises(PolicyError):
            policy.require_write()
        with self.assertRaises(PolicyError):
            policy.validate_command(["git", "status"])

    def test_parent_traversal_is_denied(self) -> None:
        policy = Policy.load(self.root)
        with self.assertRaises(PolicyError):
            policy.resolve_path("../outside.txt")

    def test_absolute_path_is_denied(self) -> None:
        policy = Policy.load(self.root)
        with self.assertRaises(PolicyError):
            policy.resolve_path(str((self.root.parent / "outside.txt").resolve()))

    def test_secret_file_names_are_denied(self) -> None:
        policy = Policy.load(self.root)
        for name in [".env", ".env.local", "private.pem", "id_rsa", "credentials.json"]:
            with self.subTest(name=name):
                with self.assertRaises(PolicyError):
                    policy.resolve_path(name)

    def test_policy_authority_file_is_protected_from_tools(self) -> None:
        self.write_policy({"allow_write": True})
        policy = Policy.load(self.root)
        with self.assertRaises(PolicyError):
            policy.resolve_path(".gpthands.json", must_exist=True)

    @unittest.skipIf(os.name == "nt", "symlink permissions vary on Windows")
    def test_symlink_escape_is_denied(self) -> None:
        outside = self.root.parent / f"gpthands-outside-{os.getpid()}.txt"
        outside.write_text("secret", encoding="utf-8")
        try:
            (self.root / "escape").symlink_to(outside)
            policy = Policy.load(self.root)
            with self.assertRaises(PolicyError):
                policy.resolve_path("escape", must_exist=True)
        finally:
            outside.unlink(missing_ok=True)

    def test_config_must_not_be_symlink(self) -> None:
        if os.name == "nt":
            self.skipTest("symlink permissions vary on Windows")
        real = self.root / "real.json"
        real.write_text("{}", encoding="utf-8")
        (self.root / ".gpthands.json").symlink_to(real)
        with self.assertRaises(PolicyError):
            Policy.load(self.root)

    @unittest.skipIf(os.name == "nt", "POSIX permission bits only")
    def test_config_must_not_be_group_or_world_writable(self) -> None:
        config = self.root / ".gpthands.json"
        config.write_text("{}", encoding="utf-8")
        config.chmod(0o666)
        try:
            with self.assertRaises(PolicyError):
                Policy.load(self.root)
        finally:
            config.chmod(0o600)

    def test_command_requires_explicit_allowlist(self) -> None:
        self.write_policy({"allow_process": True, "allowed_commands": ["git"]})
        policy = Policy.load(self.root)
        self.assertEqual(policy.validate_command(["git", "status"]), ["git", "status"])
        with self.assertRaises(PolicyError):
            policy.validate_command(["python3", "-c", "print(1)"])

    def test_network_subcommand_is_denied_by_default(self) -> None:
        self.write_policy({"allow_process": True, "allowed_commands": ["git"]})
        policy = Policy.load(self.root)
        self.assertEqual(policy.validate_command(["git", "status"]), ["git", "status"])
        with self.assertRaises(PolicyError):
            policy.validate_command(["git", "fetch"])

    def test_force_arguments_are_denied(self) -> None:
        self.write_policy({"allow_process": True, "allowed_commands": ["git"], "allow_network_commands": True})
        policy = Policy.load(self.root)
        with self.assertRaises(PolicyError):
            policy.validate_command(["git", "push", "--force"])


class AuditSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.external = self.root.parent / f"gpthands-audit-security-{os.getpid()}.jsonl"

    def tearDown(self) -> None:
        self.tmp.cleanup()
        self.external.unlink(missing_ok=True)
        (self.external.parent / f"gpthands-audit-link-{os.getpid()}.jsonl").unlink(missing_ok=True)

    def test_audit_log_must_be_outside_workspace(self) -> None:
        with self.assertRaises(OSError):
            AuditLogger(self.root / "audit.jsonl", workspace=self.root)

    @unittest.skipIf(os.name == "nt", "symlink behavior varies on Windows")
    def test_audit_log_must_not_be_symlink(self) -> None:
        self.external.write_text("", encoding="utf-8")
        link = self.external.parent / f"gpthands-audit-link-{os.getpid()}.jsonl"
        link.symlink_to(self.external)
        with self.assertRaises(OSError):
            AuditLogger(link, workspace=self.root)

    @unittest.skipIf(os.name == "nt", "POSIX permission bits only")
    def test_audit_log_is_mode_600(self) -> None:
        audit = AuditLogger(self.external, workspace=self.root)
        try:
            mode = stat.S_IMODE(self.external.stat().st_mode)
            self.assertEqual(mode, 0o600)
        finally:
            audit.close()


class ServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.audit_path = self.root.parent / f"gpthands-audit-{os.getpid()}.jsonl"

    def tearDown(self) -> None:
        self.tmp.cleanup()
        self.audit_path.unlink(missing_ok=True)

    def server(self) -> GPTHandsServer:
        return GPTHandsServer(Policy.load(self.root), AuditLogger(self.audit_path, workspace=self.root))

    def call(self, name: str, arguments: dict | None = None) -> dict:
        response = self.server().handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments or {}},
            }
        )
        assert response is not None
        return response["result"]

    def test_read_file_works_and_redacts_token(self) -> None:
        (self.root / "sample.txt").write_text("token=sk-abcdefghijklmnopqrstuv", encoding="utf-8")
        result = self.call("read_file", {"target": "sample.txt"})
        self.assertFalse(result["isError"])
        text = result["content"][0]["text"]
        self.assertIn("[REDACTED]", text)
        self.assertNotIn("sk-abcdefghijklmnopqrstuv", text)

    def test_write_is_denied_by_default(self) -> None:
        result = self.call("write_file", {"target": "new.txt", "content": "hello"})
        self.assertTrue(result["isError"])
        self.assertFalse((self.root / "new.txt").exists())

    def test_write_requires_explicit_overwrite(self) -> None:
        (self.root / ".gpthands.json").write_text(json.dumps({"allow_write": True}), encoding="utf-8")
        (self.root / "existing.txt").write_text("old", encoding="utf-8")
        server = self.server()
        denied = server.handle(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "write_file", "arguments": {"target": "existing.txt", "content": "new"}},
            }
        )
        assert denied is not None
        self.assertTrue(denied["result"]["isError"])
        self.assertEqual((self.root / "existing.txt").read_text(encoding="utf-8"), "old")

    def test_write_cannot_modify_policy_authority(self) -> None:
        original = {"allow_write": True}
        policy_path = self.root / ".gpthands.json"
        policy_path.write_text(json.dumps(original), encoding="utf-8")
        server = self.server()
        response = server.handle(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "write_file",
                    "arguments": {
                        "target": ".gpthands.json",
                        "content": json.dumps({"allow_process": True, "allowed_commands": ["python3"]}),
                        "overwrite": True,
                    },
                },
            }
        )
        assert response is not None
        self.assertTrue(response["result"]["isError"])
        self.assertEqual(json.loads(policy_path.read_text(encoding="utf-8")), original)

    def test_initialize_and_tools_list(self) -> None:
        server = self.server()
        init = server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "test-version"}})
        assert init is not None
        self.assertEqual(init["result"]["serverInfo"]["name"], "GPTHands")
        self.assertEqual(init["result"]["protocolVersion"], "test-version")
        tools = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        assert tools is not None
        names = {tool["name"] for tool in tools["result"]["tools"]}
        self.assertEqual(names, {"workspace_info", "read_file", "list_dir", "grep", "write_file", "run_command"})

    def test_audit_log_does_not_store_write_content(self) -> None:
        (self.root / ".gpthands.json").write_text(json.dumps({"allow_write": True}), encoding="utf-8")
        server = self.server()
        secret = "sk-abcdefghijklmnopqrstuv"
        response = server.handle(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "write_file", "arguments": {"target": "created.txt", "content": secret}},
            }
        )
        assert response is not None
        self.assertFalse(response["result"]["isError"])
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
