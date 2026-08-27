#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import os
import time
import zipfile
from pathlib import Path

from release_bootstrap import inspect_wheel


def _zip_time() -> tuple[int, int, int, int, int, int]:
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "315532800"))
    epoch = max(epoch, 315532800)  # ZIP minimum: 1980-01-01
    return time.gmtime(epoch)[:6]


def _add_bytes(archive: zipfile.ZipFile, name: str, data: bytes, *, executable: bool = False) -> None:
    info = zipfile.ZipInfo(name, _zip_time())
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = ((0o755 if executable else 0o644) & 0xFFFF) << 16
    archive.writestr(info, data)


def _readme(platform_name: str, wheel_name: str) -> str:
    runner = "install.ps1" if platform_name == "windows" else "./install.sh"
    return f"""GPTHands offline installer bundle\n\nPlatform: {platform_name}\nWheel: {wheel_name}\n\nInstall:\n  {runner}\n\nRollback:\n  python install.py rollback\n\nStatus:\n  python install.py status\n\nThe installer uses a versioned local virtual environment, no-index/no-deps wheel install, atomic launcher switching, and preserves prior versions for rollback. Python 3.11+ is required.\n"""


def build_bundle(*, wheel: Path, bootstrap: Path, outdir: Path, platform_name: str) -> Path:
    _, version = inspect_wheel(wheel)
    outdir.mkdir(parents=True, exist_ok=True)
    output = outdir / f"gpthands-{version}-{platform_name}.zip"
    wheel_bytes = wheel.read_bytes()
    bootstrap_bytes = bootstrap.read_bytes()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        _add_bytes(archive, wheel.name, wheel_bytes)
        _add_bytes(archive, "install.py", bootstrap_bytes, executable=True)
        _add_bytes(archive, "README.txt", _readme(platform_name, wheel.name).encode("utf-8"))
        if platform_name == "windows":
            ps = (
                "$ErrorActionPreference = 'Stop'\n"
                "$Here = Split-Path -Parent $MyInvocation.MyCommand.Path\n"
                f"python \"$Here\\install.py\" install \"$Here\\{wheel.name}\" @args\n"
            )
            _add_bytes(archive, "install.ps1", ps.encode("utf-8"))
        else:
            sh = (
                "#!/bin/sh\nset -eu\nHERE=$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\n"
                f"exec python3 \"$HERE/install.py\" install \"$HERE/{wheel.name}\" \"$@\"\n"
            )
            _add_bytes(archive, "install.sh", sh.encode("utf-8"), executable=True)
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--bootstrap", type=Path, default=Path(__file__).with_name("release_bootstrap.py"))
    parser.add_argument("--outdir", type=Path, required=True)
    args = parser.parse_args()
    outputs = [build_bundle(wheel=args.wheel, bootstrap=args.bootstrap, outdir=args.outdir, platform_name=name) for name in ("linux", "macos", "windows")]
    for path in outputs:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        print(f"{digest}  {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
