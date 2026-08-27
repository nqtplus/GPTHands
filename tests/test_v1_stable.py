from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

from gpthands.approval import ApprovalManager
from gpthands.audit import AuditLogger
from gpthands.policy import Policy
from gpthands.process_control import ProcessControlError, run_bounded_process
from gpthands.stable_server import (
    JSON_SCHEMA_2020_12,
    MCP_CURRENT,
    MCP_LEGACY,
    SERVER_INFO_META_KEY,
    V10GPTHandsServer,
)

EXPECTED_VERSION = "1.0.0rc2"


class V10StableTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name).resolve()
        self.workspace = self.base / "workspace"
        self.workspace.mkdir()
        self.state = self.base / "state"
        self.state.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _server(self):
        audit = AuditLogger(self.state / "audit.jsonl", workspace=self.workspace)
        approvals = ApprovalManager(self.state / "approval.key")
        policy = Policy(workspace=self.workspace, policy_path=self.state / "policy.json")
        return V10GPTHandsServer(policy, audit, approvals=approvals), audit, approvals

    def test_modern_discovery_needs_no_initialize(self) -> None:
        server, audit, approvals = self._server()
        try:
            response = server.handle({"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": MCP_CURRENT}}})
            assert response is not None
            result = response["result"]
            self.assertEqual(result["supportedVersions"], [MCP_CURRENT])
            self.assertEqual(result["_meta"][SERVER_INFO_META_KEY]["version"], EXPECTED_VERSION)
            self.assertGreater(result["ttlMs"], 0)
            self.assertEqual(result["cacheScope"], "private")
        finally:
            audit.close(); approvals.close()

    def test_legacy_initialize_remains_supported(self) -> None:
        server, audit, approvals = self._server()
        try:
            response = server.handle({"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {"protocolVersion": MCP_LEGACY}})
            assert response is not None
            self.assertEqual(response["result"]["protocolVersion"], MCP_LEGACY)
            self.assertEqual(response["result"]["serverInfo"]["version"], EXPECTED_VERSION)
        finally:
            audit.close(); approvals.close()

    def test_modern_tool_list_uses_json_schema_2020_12_and_server_stamp(self) -> None:
        server, audit, approvals = self._server()
        try:
            response = server.handle({
                "jsonrpc": "2.0", "id": 3, "method": "tools/list",
                "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": MCP_CURRENT}},
            })
            assert response is not None
            tools = response["result"]["tools"]
            self.assertTrue(tools)
            self.assertTrue(all(t["inputSchema"].get("$schema") == JSON_SCHEMA_2020_12 for t in tools))
            self.assertEqual(response["result"]["_meta"][SERVER_INFO_META_KEY]["name"], "GPTHands")
        finally:
            audit.close(); approvals.close()

    @unittest.skipIf(os.name == "nt", "Windows secure execution is covered by Job Object integration tests")
    def test_posix_timeout_kills_descendant_process_group(self) -> None:
        marker = self.base / "descendant-survived.txt"
        grandchild = (
            "import time,pathlib; time.sleep(2); "
            f"pathlib.Path({str(marker)!r}).write_text('LEAK', encoding='utf-8')"
        )
        parent = (
            "import subprocess,sys,time; "
            f"subprocess.Popen([sys.executable,'-c',{grandchild!r}]); time.sleep(30)"
        )
        with self.assertRaises(ProcessControlError):
            run_bounded_process(
                [sys.executable, "-c", parent],
                cwd=self.workspace,
                env={"PATH": os.environ.get("PATH", ""), "PYTHONIOENCODING": "utf-8"},
                timeout=1,
                max_output_bytes=10_000,
            )
        time.sleep(2.5)
        self.assertFalse(marker.exists(), "descendant survived process-group timeout cleanup")


if __name__ == "__main__":
    unittest.main()