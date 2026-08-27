from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


class ReleaseGateError(RuntimeError):
    pass


_STABLE_VERSION = re.compile(r"^\d+\.\d+\.\d+$")
_SHA40 = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class ReleaseGateResult:
    version: str
    stable: bool
    review_required: bool
    review_file: Path | None
    reviewed_commit: str | None
    reviewer: str | None
    report_url: str | None
    promotion_changed_files: tuple[str, ...] = ()


def is_stable_version(version: str) -> bool:
    return bool(_STABLE_VERSION.fullmatch(version))


def allowed_promotion_files(version: str) -> frozenset[str]:
    """Files allowed to change after the independently reviewed RC baseline.

    The stable promotion commit may carry review evidence, version metadata and
    release-status documentation only. Security/runtime implementation changes
    require a new external review baseline instead of being smuggled into the
    promotion commit.
    """

    return frozenset(
        {
            f"docs/reviews/v{version}.json",
            "pyproject.toml",
            "src/gpthands/__init__.py",
            "src/gpthands/stable_server.py",
            "README.md",
            "ROADMAP.md",
        }
    )


def _require_string(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ReleaseGateError(f"review metadata field {key!r} must be a non-empty string")
    return value.strip()


def _parse_completed_at(value: str) -> None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReleaseGateError("review completed_at must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ReleaseGateError("review completed_at must include a timezone")


def _normalize_changed_files(values: Iterable[str]) -> tuple[str, ...]:
    normalized: set[str] = set()
    for value in values:
        item = str(value).replace("\\", "/").strip()
        if not item:
            continue
        if item.startswith("/") or item.startswith("../") or "/../" in f"/{item}/":
            raise ReleaseGateError(f"invalid promotion path: {value!r}")
        normalized.add(item)
    return tuple(sorted(normalized))


def verify_release_gate(
    *,
    version: str,
    repository_root: Path,
    current_commit: str,
    promotion_changed_files: Iterable[str] | None = None,
) -> ReleaseGateResult:
    """Verify the stable-release review gate.

    Pre-releases such as ``1.0.0rc1`` do not require an external-review record.
    Stable ``X.Y.Z`` builds require ``docs/reviews/vX.Y.Z.json``.

    The review record points to the final independently reviewed RC baseline.
    Because adding the review record and promoting ``rcN`` to a stable version
    necessarily changes Git SHA, the stable release commit may differ from the
    reviewed baseline *only* through a tiny allowlist of promotion metadata and
    release-status documentation. Any runtime/security implementation change
    after review blocks release and requires a new review baseline.

    The record is workflow evidence, not cryptographic proof that the named
    reviewer is independent; human/process verification remains required.
    """

    root = repository_root.resolve(strict=True)
    stable = is_stable_version(version)
    if not stable:
        return ReleaseGateResult(
            version=version,
            stable=False,
            review_required=False,
            review_file=None,
            reviewed_commit=None,
            reviewer=None,
            report_url=None,
        )

    if not _SHA40.fullmatch(current_commit):
        raise ReleaseGateError("current commit must be a lowercase 40-character Git SHA")

    review_file = root / "docs" / "reviews" / f"v{version}.json"
    if review_file.is_symlink():
        raise ReleaseGateError("stable review metadata must not be a symlink")
    if not review_file.is_file():
        raise ReleaseGateError(
            f"stable release {version} requires independent review metadata at {review_file.relative_to(root)}"
        )

    try:
        data = json.loads(review_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseGateError(f"cannot read stable review metadata: {exc}") from exc
    if not isinstance(data, dict):
        raise ReleaseGateError("stable review metadata root must be an object")

    allowed = {
        "schema_version",
        "status",
        "version",
        "reviewed_commit",
        "reviewer",
        "independent_reviewer_attested",
        "completed_at",
        "report_url",
        "critical_open",
        "high_open",
        "notes",
    }
    unknown = set(data) - allowed
    if unknown:
        raise ReleaseGateError(f"unknown stable review metadata fields: {', '.join(sorted(unknown))}")

    if data.get("schema_version") != 1:
        raise ReleaseGateError("stable review metadata schema_version must be 1")
    if _require_string(data, "status") != "approved":
        raise ReleaseGateError("stable review metadata status must be 'approved'")
    if _require_string(data, "version") != version:
        raise ReleaseGateError("stable review metadata version does not match package version")

    reviewed_commit = _require_string(data, "reviewed_commit")
    if not _SHA40.fullmatch(reviewed_commit):
        raise ReleaseGateError("reviewed_commit must be a lowercase 40-character Git SHA")

    changed = _normalize_changed_files(promotion_changed_files or ())
    if reviewed_commit != current_commit:
        if promotion_changed_files is None:
            raise ReleaseGateError(
                "release commit differs from reviewed baseline but promotion diff was not supplied"
            )
        permitted = allowed_promotion_files(version)
        unexpected = set(changed) - permitted
        if unexpected:
            raise ReleaseGateError(
                "stable promotion contains unreviewed files: " + ", ".join(sorted(unexpected))
            )
        expected_review_file = f"docs/reviews/v{version}.json"
        if expected_review_file not in changed:
            raise ReleaseGateError(
                "stable promotion must add/update the exact external review metadata file"
            )

    reviewer = _require_string(data, "reviewer")
    if data.get("independent_reviewer_attested") is not True:
        raise ReleaseGateError("independent_reviewer_attested must be true")

    completed_at = _require_string(data, "completed_at")
    _parse_completed_at(completed_at)

    report_url = _require_string(data, "report_url")
    if not report_url.startswith("https://"):
        raise ReleaseGateError("report_url must use https://")

    for key in ("critical_open", "high_open"):
        value = data.get(key)
        if type(value) is not int or value < 0:
            raise ReleaseGateError(f"{key} must be a non-negative integer")
        if value != 0:
            raise ReleaseGateError(f"stable release blocked: {key} must be 0")

    notes = data.get("notes")
    if notes is not None and not isinstance(notes, str):
        raise ReleaseGateError("notes must be a string when present")

    return ReleaseGateResult(
        version=version,
        stable=True,
        review_required=True,
        review_file=review_file,
        reviewed_commit=reviewed_commit,
        reviewer=reviewer,
        report_url=report_url,
        promotion_changed_files=changed,
    )
