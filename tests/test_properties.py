from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from gpthands.approval import ApprovalError, ApprovalManager
from gpthands.policy import Policy, PolicyError
from gpthands.risk import RiskLevel

try:
    from hypothesis import given, settings, strategies as st
except ImportError:  # normal runtime and base CI intentionally have no test dependency
    HYPOTHESIS_AVAILABLE = False
else:
    HYPOTHESIS_AVAILABLE = True


if not HYPOTHESIS_AVAILABLE:
    class PropertySecurityTests(unittest.TestCase):
        @unittest.skip("Hypothesis is installed only in the adversarial CI job")
        def test_hypothesis_dependency_is_optional(self) -> None:
            pass
else:
    class PropertySecurityTests(unittest.TestCase):
        @settings(max_examples=500, deadline=None)
        @given(st.text(alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/\\ ", min_size=0, max_size=160))
        def test_any_accepted_relative_path_remains_in_workspace(self, target: str) -> None:
            with tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp).resolve()
                workspace = base / "workspace"
                workspace.mkdir()
                state = base / "state"
                state.mkdir()
                policy = Policy(workspace=workspace, policy_path=state / "policy.json")
                try:
                    resolved = policy.resolve_path(target, must_exist=False)
                except (PolicyError, OSError, ValueError):
                    return
                self.assertFalse(Path(target).is_absolute())
                self.assertEqual(os.path.commonpath((str(workspace), str(resolved))), str(workspace))

        @settings(max_examples=250, deadline=None)
        @given(st.integers(min_value=0, max_value=10_000), st.characters(min_codepoint=33, max_codepoint=126))
        def test_any_single_character_token_mutation_fails_signature(self, position: int, replacement: str) -> None:
            with tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp).resolve()
                workspace = base / "workspace"
                workspace.mkdir()
                manager = ApprovalManager(base / "approval.key", base / "used.jsonl")
                try:
                    token = manager.issue(workspace=workspace, risk=RiskLevel.EXEC, ttl_seconds=60)
                    index = position % len(token)
                    if replacement == token[index]:
                        replacement = "A" if token[index] != "A" else "B"
                    mutated = token[:index] + replacement + token[index + 1:]
                    with self.assertRaises(ApprovalError):
                        manager.validate(
                            mutated,
                            workspace=workspace,
                            minimum_risk=RiskLevel.EXEC,
                            consume=False,
                        )
                finally:
                    manager.close()


if __name__ == "__main__":
    unittest.main()
