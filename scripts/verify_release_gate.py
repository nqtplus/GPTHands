#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import tomllib
from pathlib import Path

from gpthands.release_gate import ReleaseGateError, verify_release_gate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify GPTHands stable-release security-review gate")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--commit", required=True)
    args = parser.parse_args(argv)

    root = args.root.resolve(strict=True)
    version = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    try:
        result = verify_release_gate(version=version, repository_root=root, current_commit=args.commit)
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
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
