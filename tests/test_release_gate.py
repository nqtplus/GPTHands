from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from gpthands.release_gate import ReleaseGateError, verify_release_gate


COMMIT = "a" * 40


class StableReleaseGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        (self.root / "docs" / "reviews").mkdir(parents=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _record(self, **changes) -> dict:
        data = {
            "schema_version": 1,
            "status": "approved",
            "version": "1.0.0",
            "reviewed_commit": COMMIT,
            "reviewer": "Independent Security Reviewer",
            "independent_reviewer_attested": True,
            "completed_at": "2026-08-28T00:00:00+07:00",
            "report_url": "https://example.invalid/gpthands-v1-review",
            "critical_open": 0,
            "high_open": 0,
            "notes": "example test record",
        }
        data.update(changes)
        return data

    def _write(self, data: dict) -> Path:
        target = self.root / "docs" / "reviews" / "v1.0.0.json"
        target.write_text(json.dumps(data), encoding="utf-8")
        return target

    def test_prerelease_does_not_require_external_review_record(self) -> None:
        result = verify_release_gate(
            version="1.0.0rc1", repository_root=self.root, current_commit=COMMIT
        )
        self.assertFalse(result.stable)
        self.assertFalse(result.review_required)
        self.assertIsNone(result.review_file)

    def test_stable_release_requires_review_record(self) -> None:
        with self.assertRaisesRegex(ReleaseGateError, "requires independent review metadata"):
            verify_release_gate(version="1.0.0", repository_root=self.root, current_commit=COMMIT)

    def test_approved_exact_commit_record_passes(self) -> None:
        target = self._write(self._record())
        result = verify_release_gate(version="1.0.0", repository_root=self.root, current_commit=COMMIT)
        self.assertTrue(result.stable)
        self.assertTrue(result.review_required)
        self.assertEqual(result.review_file, target)
        self.assertEqual(result.reviewed_commit, COMMIT)

    def test_reviewed_commit_must_match_release_commit(self) -> None:
        self._write(self._record(reviewed_commit="b" * 40))
        with self.assertRaisesRegex(ReleaseGateError, "differs from the externally reviewed commit"):
            verify_release_gate(version="1.0.0", repository_root=self.root, current_commit=COMMIT)

    def test_high_findings_block_stable_release(self) -> None:
        self._write(self._record(high_open=1))
        with self.assertRaisesRegex(ReleaseGateError, "high_open must be 0"):
            verify_release_gate(version="1.0.0", repository_root=self.root, current_commit=COMMIT)

    def test_independent_reviewer_attestation_is_required(self) -> None:
        self._write(self._record(independent_reviewer_attested=False))
        with self.assertRaisesRegex(ReleaseGateError, "independent_reviewer_attested must be true"):
            verify_release_gate(version="1.0.0", repository_root=self.root, current_commit=COMMIT)

    def test_unknown_fields_are_rejected(self) -> None:
        self._write(self._record(bypass=True))
        with self.assertRaisesRegex(ReleaseGateError, "unknown stable review metadata fields"):
            verify_release_gate(version="1.0.0", repository_root=self.root, current_commit=COMMIT)

    def test_report_must_be_https(self) -> None:
        self._write(self._record(report_url="http://example.invalid/report"))
        with self.assertRaisesRegex(ReleaseGateError, "report_url must use https"):
            verify_release_gate(version="1.0.0", repository_root=self.root, current_commit=COMMIT)

    def test_completed_at_requires_timezone(self) -> None:
        self._write(self._record(completed_at="2026-08-28T00:00:00"))
        with self.assertRaisesRegex(ReleaseGateError, "must include a timezone"):
            verify_release_gate(version="1.0.0", repository_root=self.root, current_commit=COMMIT)


if __name__ == "__main__":
    unittest.main()
