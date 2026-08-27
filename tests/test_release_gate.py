from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from gpthands.release_gate import ReleaseGateError, verify_release_gate


REVIEWED_COMMIT = "a" * 40
RELEASE_COMMIT = "b" * 40


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
            "reviewed_commit": REVIEWED_COMMIT,
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
            version="1.0.0rc1", repository_root=self.root, current_commit=RELEASE_COMMIT
        )
        self.assertFalse(result.stable)
        self.assertFalse(result.review_required)
        self.assertIsNone(result.review_file)

    def test_stable_release_requires_review_record(self) -> None:
        with self.assertRaisesRegex(ReleaseGateError, "requires independent review metadata"):
            verify_release_gate(
                version="1.0.0", repository_root=self.root, current_commit=RELEASE_COMMIT
            )

    def test_approved_exact_reviewed_commit_record_passes(self) -> None:
        target = self._write(self._record())
        result = verify_release_gate(
            version="1.0.0", repository_root=self.root, current_commit=REVIEWED_COMMIT
        )
        self.assertTrue(result.stable)
        self.assertTrue(result.review_required)
        self.assertEqual(result.review_file, target)
        self.assertEqual(result.reviewed_commit, REVIEWED_COMMIT)
        self.assertEqual(result.promotion_changed_files, ())

    def test_different_release_commit_requires_promotion_diff(self) -> None:
        self._write(self._record())
        with self.assertRaisesRegex(ReleaseGateError, "promotion diff was not supplied"):
            verify_release_gate(
                version="1.0.0", repository_root=self.root, current_commit=RELEASE_COMMIT
            )

    def test_minimal_stable_promotion_passes(self) -> None:
        self._write(self._record())
        changed = [
            "docs/reviews/v1.0.0.json",
            "pyproject.toml",
            "src/gpthands/__init__.py",
            "src/gpthands/stable_server.py",
            "README.md",
            "ROADMAP.md",
        ]
        result = verify_release_gate(
            version="1.0.0",
            repository_root=self.root,
            current_commit=RELEASE_COMMIT,
            promotion_changed_files=changed,
        )
        self.assertEqual(result.reviewed_commit, REVIEWED_COMMIT)
        self.assertEqual(set(result.promotion_changed_files), set(changed))

    def test_unreviewed_runtime_file_blocks_promotion(self) -> None:
        self._write(self._record())
        with self.assertRaisesRegex(ReleaseGateError, "unreviewed files"):
            verify_release_gate(
                version="1.0.0",
                repository_root=self.root,
                current_commit=RELEASE_COMMIT,
                promotion_changed_files=[
                    "docs/reviews/v1.0.0.json",
                    "src/gpthands/policy.py",
                ],
            )

    def test_promotion_must_include_exact_review_file(self) -> None:
        self._write(self._record())
        with self.assertRaisesRegex(ReleaseGateError, "must add/update the exact external review metadata"):
            verify_release_gate(
                version="1.0.0",
                repository_root=self.root,
                current_commit=RELEASE_COMMIT,
                promotion_changed_files=["pyproject.toml"],
            )

    def test_high_findings_block_stable_release(self) -> None:
        self._write(self._record(high_open=1))
        with self.assertRaisesRegex(ReleaseGateError, "high_open must be 0"):
            verify_release_gate(
                version="1.0.0", repository_root=self.root, current_commit=REVIEWED_COMMIT
            )

    def test_independent_reviewer_attestation_is_required(self) -> None:
        self._write(self._record(independent_reviewer_attested=False))
        with self.assertRaisesRegex(ReleaseGateError, "independent_reviewer_attested must be true"):
            verify_release_gate(
                version="1.0.0", repository_root=self.root, current_commit=REVIEWED_COMMIT
            )

    def test_unknown_fields_are_rejected(self) -> None:
        self._write(self._record(bypass=True))
        with self.assertRaisesRegex(ReleaseGateError, "unknown stable review metadata fields"):
            verify_release_gate(
                version="1.0.0", repository_root=self.root, current_commit=REVIEWED_COMMIT
            )

    def test_report_must_be_https(self) -> None:
        self._write(self._record(report_url="http://example.invalid/report"))
        with self.assertRaisesRegex(ReleaseGateError, "report_url must use https"):
            verify_release_gate(
                version="1.0.0", repository_root=self.root, current_commit=REVIEWED_COMMIT
            )

    def test_completed_at_requires_timezone(self) -> None:
        self._write(self._record(completed_at="2026-08-28T00:00:00"))
        with self.assertRaisesRegex(ReleaseGateError, "must include a timezone"):
            verify_release_gate(
                version="1.0.0", repository_root=self.root, current_commit=REVIEWED_COMMIT
            )


if __name__ == "__main__":
    unittest.main()
