from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_release_gate.py"


@unittest.skipIf(shutil.which("git") is None, "git is required for stable release-gate integration test")
class StableReleaseGitIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self._git("init")
        self._git("config", "user.name", "GPTHands CI")
        self._git("config", "user.email", "ci@gpthands.invalid")
        (self.root / "docs" / "reviews").mkdir(parents=True)
        (self.root / "src" / "gpthands").mkdir(parents=True)
        (self.root / "README.md").write_text("RC\n", encoding="utf-8")
        (self.root / "ROADMAP.md").write_text("RC\n", encoding="utf-8")
        (self.root / "pyproject.toml").write_text(
            '[project]\nname = "gpthands"\nversion = "1.0.0rc1"\n', encoding="utf-8"
        )
        (self.root / "src" / "gpthands" / "__init__.py").write_text(
            '__version__ = "1.0.0rc1"\n', encoding="utf-8"
        )
        (self.root / "src" / "gpthands" / "stable_server.py").write_text(
            'VERSION = "1.0.0rc1"\n', encoding="utf-8"
        )
        self._git("add", ".")
        self._git("commit", "-m", "reviewed rc baseline")
        self.reviewed = self._git("rev-parse", "HEAD").strip()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _git(self, *args: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(self.root), *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            shell=False,
            check=False,
            timeout=30,
        )
        if completed.returncode != 0:
            self.fail(f"git {' '.join(args)} failed:\n{completed.stdout}")
        return completed.stdout

    def _promote(self, *, poison_version_file: bool = False) -> str:
        (self.root / "pyproject.toml").write_text(
            '[project]\nname = "gpthands"\nversion = "1.0.0"\n', encoding="utf-8"
        )
        (self.root / "src" / "gpthands" / "__init__.py").write_text(
            '__version__ = "1.0.0"\n', encoding="utf-8"
        )
        stable_text = 'VERSION = "1.0.0"\n'
        if poison_version_file:
            stable_text += 'UNREVIEWED_CODE = "should block stable release"\n'
        (self.root / "src" / "gpthands" / "stable_server.py").write_text(
            stable_text, encoding="utf-8"
        )
        review = {
            "schema_version": 1,
            "status": "approved",
            "version": "1.0.0",
            "reviewed_commit": self.reviewed,
            "reviewer": "Independent Reviewer",
            "independent_reviewer_attested": True,
            "completed_at": "2026-08-28T00:00:00+07:00",
            "report_url": "https://example.invalid/report",
            "critical_open": 0,
            "high_open": 0,
        }
        (self.root / "docs" / "reviews" / "v1.0.0.json").write_text(
            json.dumps(review), encoding="utf-8"
        )
        self._git("add", ".")
        self._git("commit", "-m", "promote reviewed rc to stable")
        return self._git("rev-parse", "HEAD").strip()

    def _gate(self, commit: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(self.root), "--commit", commit],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            shell=False,
            check=False,
            timeout=30,
        )

    def test_minimal_reviewed_promotion_passes(self) -> None:
        stable = self._promote()
        completed = self._gate(stable)
        self.assertEqual(completed.returncode, 0, completed.stdout)
        payload = json.loads(completed.stdout)
        self.assertTrue(payload["stable"])
        self.assertEqual(payload["reviewed_commit"], self.reviewed)
        self.assertIn("docs/reviews/v1.0.0.json", payload["promotion_changed_files"])

    def test_unreviewed_code_after_baseline_blocks_release(self) -> None:
        self._promote()
        (self.root / "src" / "gpthands" / "policy.py").write_text("UNREVIEWED = True\n", encoding="utf-8")
        self._git("add", ".")
        self._git("commit", "-m", "unreviewed runtime change")
        head = self._git("rev-parse", "HEAD").strip()
        completed = self._gate(head)
        self.assertEqual(completed.returncode, 2, completed.stdout)
        self.assertIn("unreviewed files", completed.stdout)
        self.assertIn("src/gpthands/policy.py", completed.stdout)

    def test_unreviewed_code_hidden_in_version_file_blocks_release(self) -> None:
        stable = self._promote(poison_version_file=True)
        completed = self._gate(stable)
        self.assertEqual(completed.returncode, 2, completed.stdout)
        self.assertIn("changes beyond exact", completed.stdout)
        self.assertIn("stable_server.py", completed.stdout)


if __name__ == "__main__":
    unittest.main()
