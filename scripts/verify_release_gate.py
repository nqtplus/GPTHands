#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from gpthands.release_gate import ReleaseGateError, is_stable_version, verify_release_gate


_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_VERSION_FILES = (
    "pyproject.toml",
    "src/gpthands/__init__.py",
    "src/gpthands/stable_server.py",
)


def _run_git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        shell=False,
        check=False,
        timeout=30,
    )


def _git_show(root: Path, commit: str, path: str) -> str:
    completed = _run_git(root, "show", f"{commit}:{path}")
    if completed.returncode != 0:
        raise ReleaseGateError(
            f"cannot read reviewed baseline file {path!r}: {completed.stdout.strip()[:500]}"
        )
    return completed.stdout


def _validate_version_only_promotion(
    root: Path,
    *,
    reviewed_commit: str,
    stable_version: str,
    changed_files: list[str],
) -> None:
    """Reject executable/package changes disguised as a stable version bump."""

    baseline_pyproject = _git_show(root, reviewed_commit, "pyproject.toml")
    try:
        reviewed_version = tomllib.loads(baseline_pyproject)["project"]["version"]
    except (tomllib.TOMLDecodeError, KeyError, TypeError) as exc:
        raise ReleaseGateError("cannot determine reviewed baseline package version") from exc
    if not isinstance(reviewed_version, str):
        raise ReleaseGateError("reviewed baseline package version must be a string")
    prerelease_pattern = re.compile(re.escape(stable_version) + r"(?:a|b|rc)\d+")
    if not prerelease_pattern.fullmatch(reviewed_version):
        raise ReleaseGateError(
            f"reviewed baseline version {reviewed_version!r} is not a direct prerelease of stable {stable_version!r}"
        )

    changed = set(changed_files)
    missing = set(_VERSION_FILES) - changed
    if missing:
        raise ReleaseGateError(
            "stable promotion must update all synchronized version files: " + ", ".join(sorted(missing))
        )

    for path in _VERSION_FILES:
        baseline = _git_show(root, reviewed_commit, path)
        expected = baseline.replace(reviewed_version, stable_version)
        if expected == baseline:
            raise ReleaseGateError(
                f"reviewed baseline file {path!r} does not contain version {reviewed_version!r}; cannot prove version-only promotion"
            )
        try:
            current = (root / path).read_text(encoding="utf-8")
        except OSError as exc:
            raise ReleaseGateError(f"cannot read stable promotion file {path!r}: {exc}") from exc
        if current != expected:
            raise ReleaseGateError(
                f"stable promotion file {path!r} contains changes beyond exact {reviewed_version!r} -> {stable_version!r} substitution"
            )


def _promotion_diff(root: Path, *, version: str, current_commit: str) -> tuple[str, list[str]]:
    review_path = root / "docs" / "reviews" / f"v{version}.json"
    try:
        raw = json.loads(review_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseGateError(f"cannot read stable review metadata before Git verification: {exc}") from exc
    if not isinstance(raw, dict):
        raise ReleaseGateError("stable review metadata root must be an object")
    reviewed_commit = raw.get("reviewed_commit")
    if not isinstance(reviewed_commit, str) or not _SHA40.fullmatch(reviewed_commit):
        raise ReleaseGateError("reviewed_commit must be a lowercase 40-character Git SHA")

    if reviewed_commit == current_commit:
        return reviewed_commit, []

    ancestor = _run_git(root, "merge-base", "--is-ancestor", reviewed_commit, current_commit)
    if ancestor.returncode != 0:
        raise ReleaseGateError(
            "reviewed_commit is not an ancestor of the stable release commit; fetch full history and review the correct baseline"
        )

    diff = _run_git(root, "diff", "--name-only", f"{reviewed_commit}..{current_commit}")
    if diff.returncode != 0:
        raise ReleaseGateError(f"cannot inspect stable promotion diff: {diff.stdout.strip()[:500]}")
    changed = [line.strip() for line in diff.stdout.splitlines() if line.strip()]
    _validate_version_only_promotion(
        root,
        reviewed_commit=reviewed_commit,
        stable_version=version,
        changed_files=changed,
    )
    return reviewed_commit, changed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify GPTHands stable-release security-review gate")
    parser.add_argument("--root", type=Path, default=REPOSITORY_ROOT)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args(argv)

    root = args.root.resolve(strict=True)
    version = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    try:
        changed_files = None
        if is_stable_version(version):
            _reviewed_commit, changed_files = _promotion_diff(
                root, version=version, current_commit=args.commit
            )
        result = verify_release_gate(
            version=version,
            repository_root=root,
            current_commit=args.commit,
            promotion_changed_files=changed_files,
        )
    except ReleaseGateError as exc:
        print(f"stable release gate refused: {exc}", file=sys.stderr)
        return 2

    print(json.dumps({
        "version": result.version,
        "stable": result.stable,
        "review_required": result.review_required,
        "review_file": str(result.review_file.relative_to(root)) if result.review_file else None,
        "reviewed_commit": result.reviewed_commit,
        "reviewer": result.reviewer,
        "report_url": result.report_url,
        "promotion_changed_files": list(result.promotion_changed_files),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
