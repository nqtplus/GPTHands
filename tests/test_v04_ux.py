from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from gpthands.approval import ApprovalManager
from gpthands.audit import AuditLogger
from gpthands.control_ui import create_control_server
from gpthands.credentials import CredentialStore, CredentialStoreError
from gpthands.installer import UserInstaller
from gpthands.policy import Policy
from gpthands.trust import WorkspaceTrustStore
from gpthands.tunnel import TunnelError, build_tunnel_plan
from gpthands.ux_server import V04GPTHandsServer


class V04UXTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name).resolve()
        self.workspace = self.base / "workspace"
        self.workspace.mkdir()
        self.state = self.base / "state"
        self.state.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_explicit_workspace_trust_round_trip(self) -> None:
        store = WorkspaceTrustStore(self.state / "trust.json")
        self.assertFalse(store.is_trusted(self.workspace))
        record = store.trust(self.workspace, label="demo")
        self.assertEqual(record["path"], str(self.workspace))
        self.assertTrue(store.is_trusted(self.workspace))
        rows = store.list()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["label"], "demo")
        self.assertTrue(store.untrust(self.workspace))
        self.assertFalse(store.is_trusted(self.workspace))

    def test_tunnel_plan_uses_official_client_env_secret_reference_and_loopback_health(self) -> None:
        fake = self.base / ("tunnel-client.exe" if os.name == "nt" else "tunnel-client")
        fake.write_text("stub", encoding="utf-8")
        tunnel_id = "tunnel_" + "a" * 32
        plan = build_tunnel_plan(workspace=self.workspace, tunnel_id=tunnel_id, binary=str(fake))
        joined = " ".join(plan.init_argv)
        self.assertIn("env:CONTROL_PLANE_API_KEY", joined)
        self.assertIn("127.0.0.1:0", joined)
        self.assertIn("gpthands", joined)
        self.assertIn("serve", joined)
        self.assertNotIn("sk-", joined)
        with self.assertRaises(TunnelError):
            build_tunnel_plan(workspace=self.workspace, tunnel_id="bad", binary=str(fake))

    def test_control_ui_is_hard_bound_to_ipv4_loopback(self) -> None:
        server = create_control_server(self.workspace, port=0)
        try:
            self.assertEqual(server.server_address[0], "127.0.0.1")
            self.assertGreater(server.server_address[1], 0)
            self.assertGreaterEqual(len(server.csrf_token), 32)
        finally:
            server.server_close()

    def test_installer_uninstall_restores_preexisting_launcher(self) -> None:
        bin_dir = self.base / "bin"
        bin_dir.mkdir()
        suffix = ".cmd" if os.name == "nt" else ""
        original = bin_dir / f"gpthands-ui{suffix}"
        original.write_text("ORIGINAL", encoding="utf-8")
        installer = UserInstaller(bin_dir=bin_dir, manifest=self.state / "manifest.json")
        installed = installer.install()
        self.assertEqual(installed["version"], 1)
        self.assertNotEqual(original.read_text(encoding="utf-8"), "ORIGINAL")
        result = installer.uninstall()
        self.assertIn(str(original), result["restored"])
        self.assertEqual(original.read_text(encoding="utf-8"), "ORIGINAL")

    def test_v04_server_advertises_version(self) -> None:
        audit = AuditLogger(self.state / "audit.jsonl", workspace=self.workspace)
        approvals = ApprovalManager(self.state / "approval.key")
        try:
            policy = Policy(workspace=self.workspace, policy_path=self.state / "policy.json")
            server = V04GPTHandsServer(policy, audit, approvals=approvals)
            response = server.handle({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18"},
            })
            assert response is not None
            self.assertEqual(response["result"]["serverInfo"]["version"], "0.4.0")
            self.assertIn("workspace trust", response["result"]["instructions"])
        finally:
            audit.close()
            approvals.close()

    def test_credential_store_has_no_plaintext_fallback(self) -> None:
        store = CredentialStore()
        with mock.patch("gpthands.credentials.platform.system", return_value="Linux"), mock.patch(
            "gpthands.credentials.shutil.which", return_value=None
        ):
            with self.assertRaises(CredentialStoreError):
                store.backend()


if __name__ == "__main__":
    unittest.main()
