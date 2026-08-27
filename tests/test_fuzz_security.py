from __future__ import annotations

import os
import random
import string
import tempfile
import unittest
from pathlib import Path

from gpthands.approval import ApprovalError, ApprovalManager
from gpthands.audit import AuditLogger
from gpthands.limits import V03GPTHandsServer
from gpthands.policy import Policy, PolicyError
from gpthands.risk import RiskLevel


class AdversarialFuzzTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name).resolve()
        self.workspace = self.base / "workspace"
        self.workspace.mkdir()
        self.state = self.base / "state"
        self.state.mkdir()
        self.rng = random.Random(0x47505448)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _text(self, minimum: int = 0, maximum: int = 80) -> str:
        alphabet = string.ascii_letters + string.digits + "._-/\\:;[]{}()$%!?~ \t"
        return "".join(self.rng.choice(alphabet) for _ in range(self.rng.randint(minimum, maximum)))

    def test_random_paths_never_resolve_outside_workspace(self) -> None:
        policy = Policy(workspace=self.workspace, policy_path=self.state / "policy.json")
        for _ in range(1500):
            pieces = [
                self.rng.choice(["..", ".", "src", "x", ".env", ".ssh", self._text(1, 12)])
                for _ in range(self.rng.randint(1, 8))
            ]
            target = os.sep.join(pieces)
            try:
                resolved = policy.resolve_path(target, must_exist=False)
            except (PolicyError, OSError, ValueError):
                continue
            common = os.path.commonpath((str(self.workspace), str(resolved)))
            self.assertEqual(common, str(self.workspace), target)

    def test_random_approval_tokens_fail_closed(self) -> None:
        manager = ApprovalManager(self.state / "approval.key", self.state / "used.jsonl")
        try:
            valid = manager.issue(workspace=self.workspace, risk=RiskLevel.EXEC, ttl_seconds=60)
            corpus = [self._text(0, 200) for _ in range(600)]
            corpus.extend([
                valid[:-1],
                valid + "x",
                "." + valid,
                valid.replace(".", "", 1),
                valid.split(".", 1)[0] + ".AAAA",
            ])
            for token in corpus:
                with self.subTest(token=token[:30]):
                    with self.assertRaises(ApprovalError):
                        manager.validate(
                            token,
                            workspace=self.workspace,
                            minimum_risk=RiskLevel.EXEC,
                            consume=False,
                        )
        finally:
            manager.close()

    def test_random_jsonrpc_shapes_do_not_escape_exception_boundary(self) -> None:
        audit = AuditLogger(self.state / "audit.jsonl", workspace=self.workspace)
        approvals = ApprovalManager(self.state / "approval.key", self.state / "used.jsonl")
        try:
            policy = Policy(
                workspace=self.workspace,
                policy_path=self.state / "policy.json",
                max_requests_per_minute=6000,
            )
            server = V03GPTHandsServer(policy, audit, approvals=approvals)
            methods = ["initialize", "ping", "tools/list", "tools/call", self._text(1, 20)]
            for index in range(250):
                method = self.rng.choice(methods)
                params = self.rng.choice([
                    {},
                    None,
                    [],
                    "bad",
                    {"name": self._text(0, 25), "arguments": {}},
                    {"name": "read_file", "arguments": {"target": self._text(0, 60)}},
                ])
                message = {"jsonrpc": "2.0", "id": index, "method": method, "params": params}
                try:
                    response = server.handle(message)
                except Exception as exc:  # pragma: no cover - this is the invariant
                    self.fail(f"unhandled exception for fuzz message: {type(exc).__name__}: {exc}")
                self.assertIsInstance(response, dict)
        finally:
            audit.close()
            approvals.close()


if __name__ == "__main__":
    unittest.main()
