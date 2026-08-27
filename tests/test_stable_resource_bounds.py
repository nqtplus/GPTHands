from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from gpthands.approval import ApprovalManager
from gpthands.audit import AuditLogger
from gpthands.policy import Policy
from gpthands.stable_server import V10GPTHandsServer


class StableResourceBoundsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name).resolve()
        self.workspace = self.base / "workspace"
        self.workspace.mkdir()
        self.state = self.base / "state"
        self.state.mkdir()
        self.policy_path = self.state / "policy.json"
        future = time.time() + 300
        self.policy_path.write_text(
            json.dumps({
                "schema_version": 3,
                "allow_write": True,
                "write_lease_until": future,
                "max_read_bytes": 1024,
                "max_write_bytes": 1024,
                "approval_required_from": "EXEC",
                "require_os_sandbox": False,
            }),
            encoding="utf-8",
        )
        if os.name != "nt":
            os.chmod(self.policy_path, 0o600)
        self.audit = AuditLogger(self.state / "audit.jsonl", workspace=self.workspace)
        self.approvals = ApprovalManager(self.state / "approval.key")
        self.server = V10GPTHandsServer(
            Policy.load(self.workspace, self.policy_path),
            self.audit,
            approvals=self.approvals,
        )

    def tearDown(self) -> None:
        self.audit.close()
        self.approvals.close()
        self.tmp.cleanup()

    def call(self, name: str, arguments: dict) -> dict:
        response = self.server.handle({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        })
        assert response is not None
        return response["result"]

    def test_read_file_refuses_oversized_file_before_returning_content(self) -> None:
        (self.workspace / "large.txt").write_bytes(b"A" * 4096)
        result = self.call("read_file", {"target": "large.txt"})
        self.assertTrue(result["isError"])
        self.assertIn("bounded read limit", result["content"][0]["text"])
        self.assertNotIn("AAAA", result["content"][0]["text"])

    def test_preview_edit_refuses_oversized_existing_file(self) -> None:
        (self.workspace / "large.txt").write_bytes(b"B" * 4096)
        result = self.call("preview_edit", {"target": "large.txt", "new_content": "small"})
        self.assertTrue(result["isError"])
        self.assertIn("bounded read limit", result["content"][0]["text"])

    def test_regex_grep_is_disabled_but_literal_search_remains_available(self) -> None:
        (self.workspace / "data.txt").write_text("alpha beta\n", encoding="utf-8")
        denied = self.call("grep", {"pattern": "(a+)+$", "target": ".", "regex": True})
        self.assertTrue(denied["isError"])
        self.assertIn("regex grep is disabled", denied["content"][0]["text"])
        allowed = self.call("grep", {"pattern": "alpha", "target": ".", "regex": False})
        self.assertFalse(allowed["isError"])
        self.assertIn("data.txt", allowed["content"][0]["text"])


if __name__ == "__main__":
    unittest.main()
