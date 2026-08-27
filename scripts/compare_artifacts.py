from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def inventory(directory: Path) -> dict[str, str]:
    return {
        path.name: digest(path)
        for path in sorted(directory.iterdir())
        if path.is_file()
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("first", type=Path)
    parser.add_argument("second", type=Path)
    args = parser.parse_args()
    first = inventory(args.first)
    second = inventory(args.second)
    if first != second:
        print("artifact sets are not reproducible")
        print("first:", first)
        print("second:", second)
        return 1
    print("reproducible artifacts:", first)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
