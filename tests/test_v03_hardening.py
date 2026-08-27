from __future__ import annotations

import json
import multiprocessing as mp
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path

from gpthands.approval import ApprovalError, ApprovalManager
from gpthands.audit import AuditLogger, verify_audit_file
from gpthands.limits import ActionLimiter, LimitError, V03GPTHandsServer
from gpthands.policy import POLICY_SCHEMA_VERSION, Policy, PolicyError, migrate_policy_data
from gpthands.risk import RiskLevel


def _consume_worker(key: str, used: str, workspace: str, token: str, start, queue) -> None:
    manager = ApprovalManager(Path(key), Path(used))
    try:
        start.wait(10)
        try:
            manager.validate(token, workspace=Path(workspace), minimum_risk=RiskLevel.EXEC)
        except ApprovalError:
            queue.put("rejected")
        else:
            queue.put("accepted")
    finally:
        manager.close()


def _audit_worker(path: str, workspace: str, worker_id: int, count: int, start, queue) -> None:
    try:
        logger = AuditLogger(Path(path), workspace=Path(workspace))
        try:
            start.wait(10)
            for index in range(count):
                logger.record(
                    request_id=f"{worker_id}:{index}",
                    tool="worker",
                    outcome="allowed",
                    detail={"worker": worker_id, "index": index},
                )
        finally:
            logger.close()
        queue.put(None)
    except Exception as exc:  # pragma: no cover - only used to surface child failures
        queue.put(repr(exc))


class V03HardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name).resolve()
        self.workspace = self.base / "workspace"
        self.workspace.mkdir()
        self.state = self.base / "state"
        self.state.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_audit_hash_chain_detects_record_tampering(self) -> None:
        path = self.state / "audit.jsonl"
        logger = AuditLogger(path, workspace=self.workspace)
        logger.record(request_id=1, tool="read_file", outcome="allowed", detail={"target": "a.txt"})
        logger.record(request_id=2, tool="write_file", outcome="denied_or_failed", detail={"target": "b.txt"})
        logger.close()

        verified = verify_audit_file(path)
        self.assertTrue(verified.valid)
        self.assertTrue(verified.anchored)
        self.assertEqual(verified.chained_records, 2)

        rows = path.read_text(encoding="utf-8").splitlines()
        first = json.loads(rows[0])
        first["tool"] = "tampered"
        rows[0] = json.dumps(first, sort_keys=True)
        path.write_text("\n".join(rows) + "\n", encoding="utf-8")
        if os.name != "nt":
            os.chmod(path, 0o600)

        broken = verify_audit_file(path)
        self.assertFalse(broken.valid)
        with self.assertRaises(OSError):
            AuditLogger(path, workspace=self.workspace)

    def test_legacy_audit_prefix_is_anchored_by_first_v03_record(self) -> None:
        path = self.state / "audit.jsonl"
        path.write_text(json.dumps({"tool": "legacy", "outcome": "allowed"}) + "\n", encoding="utf-8")
        if os.name != "nt":
            os.chmod(path, 0o600)
        logger = AuditLogger(path, workspace=self.workspace)
        logger.record(request_id=1, tool="new", outcome="allowed")
        logger.close()

        verified = verify_audit_file(path)
        self.assertTrue(verified.valid)
        self.assertEqual(verified.legacy_records, 1)
        self.assertEqual(verified.chained_records, 1)

        data = path.read_bytes().replace(b'"legacy"', b'"changed"', 1)
        path.write_bytes(data)
        if os.name != "nt":
            os.chmod(path, 0o600)
        self.assertFalse(verify_audit_file(path).valid)

    @unittest.skipIf(os.name == "nt", "multiprocessing timing differs on Windows CI")
    def test_audit_chain_is_serialized_across_processes(self) -> None:
        path = self.state / "audit.jsonl"
        start = mp.Event()
        queue = mp.Queue()
        workers = [
            mp.Process(target=_audit_worker, args=(str(path), str(self.workspace), index, 8, start, queue))
            for index in range(2)
        ]
        for process in workers:
            process.start()
        start.set()
        for process in workers:
            process.join(15)
            self.assertEqual(process.exitcode, 0)
        errors = [queue.get(timeout=2) for _ in workers]
        self.assertEqual(errors, [None, None])
        verified = verify_audit_file(path)
        self.assertTrue(verified.valid, verified.error)
        self.assertEqual(verified.chained_records, 16)

    @unittest.skipIf(os.name == "nt", "multiprocessing timing differs on Windows CI")
    def test_approval_token_can_only_be_consumed_by_one_process(self) -> None:
        key = self.state / "approval.key"
        used = self.state / "used.jsonl"
        issuer = ApprovalManager(key, used)
        token = issuer.issue(workspace=self.workspace, risk=RiskLevel.EXEC, ttl_seconds=60)
        issuer.close()

        start = mp.Event()
        queue = mp.Queue()
        workers = [
            mp.Process(target=_consume_worker, args=(str(key), str(used), str(self.workspace), token, start, queue))
            for _ in range(2)
        ]
        for process in workers:
            process.start()
        start.set()
        for process in workers:
            process.join(15)
            self.assertEqual(process.exitcode, 0)
        results = sorted(queue.get(timeout=2) for _ in workers)
        self.assertEqual(results, ["accepted", "rejected"])

    def test_policy_schema_migrates_legacy_and_rejects_unknown_fields(self) -> None:
        legacy = migrate_policy_data({"allow_write": False, "allowed_commands": []})
        self.assertEqual(legacy["schema_version"], POLICY_SCHEMA_VERSION)

        v1 = migrate_policy_data({"schema_version": 1, "allow_network": False})
        self.assertEqual(v1["schema_version"], POLICY_SCHEMA_VERSION)
        self.assertIn("allow_network_commands", v1)
        self.assertNotIn("allow_network", v1)

        with self.assertRaises(PolicyError):
            migrate_policy_data({"schema_version": POLICY_SCHEMA_VERSION, "allow_wirte": True})
        with self.assertRaises(PolicyError):
            migrate_policy_data({"schema_version": POLICY_SCHEMA_VERSION + 1})

    def test_policy_quota_bounds(self) -> None:
        path = self.state / "policy.json"
        path.write_text(json.dumps({"schema_version": 3, "max_concurrent_actions": 0}), encoding="utf-8")
        if os.name != "nt":
            os.chmod(path, 0o600)
        with self.assertRaises(PolicyError):
            Policy.load(self.workspace, path)

    def test_rate_limiter_rejects_burst_over_limit(self) -> None:
        limiter = ActionLimiter(requests_per_minute=2, max_concurrent=2, queue_seconds=0)
        with limiter.action():
            pass
        with limiter.action():
            pass
        with self.assertRaises(LimitError):
            with limiter.action():
                pass

    def test_concurrency_limiter_rejects_when_queue_budget_is_zero(self) -> None:
        limiter = ActionLimiter(requests_per_minute=100, max_concurrent=1, queue_seconds=0)
        entered = threading.Event()
        release = threading.Event()

        def hold_slot() -> None:
            with limiter.action():
                entered.set()
                release.wait(5)

        thread = threading.Thread(target=hold_slot)
        thread.start()
        self.assertTrue(entered.wait(2))
        try:
            with self.assertRaises(LimitError):
                with limiter.action():
                    pass
        finally:
            release.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())

    def test_v03_server_advertises_version_and_limits(self) -> None:
        audit = AuditLogger(self.state / "audit.jsonl", workspace=self.workspace)
        approvals = ApprovalManager(self.state / "approval.key")
        try:
            policy = Policy(workspace=self.workspace, policy_path=self.state / "policy.json")
            server = V03GPTHandsServer(policy, audit, approvals=approvals)
            response = server.handle({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18"},
            })
            assert response is not None
            self.assertEqual(response["result"]["serverInfo"]["version"], "0.3.0")
            info = server.handle({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "workspace_info", "arguments": {}},
            })
            assert info is not None
            payload = json.loads(info["result"]["content"][0]["text"])
            self.assertEqual(payload["policy_schema_version"], POLICY_SCHEMA_VERSION)
            self.assertIn("limits", payload)
        finally:
            audit.close()
            approvals.close()


if __name__ == "__main__":
    unittest.main()
