from __future__ import annotations

import json
import os
import random
import stat
import string
import tempfile
import time
import unittest
from pathlib import Path

from gpthands.policy import POLICY_SCHEMA_VERSION, Policy, PolicyError


class PolicyFuzzTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name).resolve()
        self.workspace = self.base / "workspace"
        self.workspace.mkdir()
        self.state = self.base / "state"
        self.state.mkdir()
        self.policy_path = self.state / "policy.json"
        self.rng = random.Random(0x50303131)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write(self, value) -> None:
        self.policy_path.write_text(json.dumps(value), encoding="utf-8")
        if os.name != "nt":
            os.chmod(self.policy_path, 0o600)

    def _random_value(self):
        choices = [
            None,
            True,
            False,
            self.rng.randint(-10000, 100000),
            self.rng.random() * 100000,
            "".join(self.rng.choice(string.printable[:90]) for _ in range(self.rng.randint(0, 30))),
            [],
            {},
            ["git"],
            [1, 2, 3],
        ]
        return self.rng.choice(choices)

    def test_random_policy_objects_only_load_when_all_invariants_hold(self) -> None:
        known = [
            "schema_version",
            "allow_write",
            "allow_process",
            "allow_network_commands",
            "write_lease_until",
            "process_lease_until",
            "network_lease_until",
            "allowed_commands",
            "approval_required_from",
            "require_os_sandbox",
            "max_read_bytes",
            "max_write_bytes",
            "max_command_seconds",
            "max_output_bytes",
            "max_requests_per_minute",
            "max_concurrent_actions",
            "max_queue_seconds",
        ]
        for _ in range(700):
            raw = {}
            for field in self.rng.sample(known, self.rng.randint(0, min(8, len(known)))):
                raw[field] = self._random_value()
            if self.rng.random() < 0.2:
                raw["unknown_" + str(self.rng.randint(0, 999))] = self._random_value()
            self._write(raw)
            try:
                loaded = Policy.load(self.workspace, self.policy_path)
            except (PolicyError, OSError, ValueError, TypeError, OverflowError):
                continue
            self.assertEqual(loaded.schema_version, POLICY_SCHEMA_VERSION)
            self.assertGreaterEqual(loaded.max_requests_per_minute, 1)
            self.assertLessEqual(loaded.max_requests_per_minute, 6000)
            self.assertGreaterEqual(loaded.max_concurrent_actions, 1)
            self.assertLessEqual(loaded.max_concurrent_actions, 64)
            self.assertGreaterEqual(loaded.max_queue_seconds, 0)
            self.assertLessEqual(loaded.max_queue_seconds, 30)
            for expiry in (loaded.write_lease_until, loaded.process_lease_until, loaded.network_lease_until):
                if expiry is not None:
                    self.assertLessEqual(expiry, time.time() + 86402)

    def test_non_object_policy_roots_are_rejected(self) -> None:
        for value in (None, [], "text", 3, True):
            with self.subTest(value=value):
                self._write(value)
                with self.assertRaises(PolicyError):
                    Policy.load(self.workspace, self.policy_path)

    def test_unknown_field_typo_is_rejected_not_ignored(self) -> None:
        self._write({"schema_version": 3, "allow_wirte": True})
        with self.assertRaises(PolicyError):
            Policy.load(self.workspace, self.policy_path)

    @unittest.skipIf(os.name == "nt", "POSIX mode check")
    def test_group_writable_policy_is_always_rejected(self) -> None:
        self._write({"schema_version": 3})
        os.chmod(self.policy_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IWGRP)
        with self.assertRaises(PolicyError):
            Policy.load(self.workspace, self.policy_path)


if __name__ == "__main__":
    unittest.main()
