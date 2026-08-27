#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "scripts" / "release_bootstrap.py"
CURRENT_VERSION = "1.0.0"
OLD_VERSION = "0.9.999"


def run(*argv: str, cwd: Path = ROOT) -> str:
    completed = subprocess.run(
        list(argv), cwd=cwd, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, shell=False, timeout=240, check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"command failed ({completed.returncode}): {' '.join(argv)}\n{completed.stdout}")
    return completed.stdout


def clean_build() -> None:
    for name in ("build", "src/gpthands.egg-info"):
        path = ROOT / name
        if path.exists():
            shutil.rmtree(path)


def build(outdir: Path) -> Path:
    clean_build()
    run(sys.executable, "-m", "build", "--wheel", "--no-isolation", "--outdir", str(outdir))
    wheels = list(outdir.glob("*.whl"))
    if len(wheels) != 1:
        raise RuntimeError(f"expected one wheel in {outdir}, got {wheels}")
    return wheels[0]


def bootstrap(root: Path, bin_dir: Path, *args: str) -> dict:
    output = run(sys.executable, str(BOOTSTRAP), "--root", str(root), "--bin-dir", str(bin_dir), *args)
    return json.loads(output)


def main() -> int:
    pyproject = ROOT / "pyproject.toml"
    original = pyproject.read_text(encoding="utf-8")
    if f'version = "{CURRENT_VERSION}"' not in original:
        raise RuntimeError("unexpected current version")
    with tempfile.TemporaryDirectory(prefix="gpthands-installer-smoke-") as tmp:
        base = Path(tmp)
        old_out = base / "old-wheel"; old_out.mkdir()
        new_out = base / "new-wheel"; new_out.mkdir()
        install_root = base / "install-root"
        bin_dir = base / "bin"
        try:
            pyproject.write_text(original.replace(f'version = "{CURRENT_VERSION}"', f'version = "{OLD_VERSION}"', 1), encoding="utf-8")
            old_wheel = build(old_out)
        finally:
            pyproject.write_text(original, encoding="utf-8")
        new_wheel = build(new_out)

        first = bootstrap(install_root, bin_dir, "install", str(old_wheel))
        assert first["current"] == OLD_VERSION, first
        second = bootstrap(install_root, bin_dir, "install", str(new_wheel))
        assert second["current"] == CURRENT_VERSION and OLD_VERSION in second["history"], second
        rolled = bootstrap(install_root, bin_dir, "rollback")
        assert rolled["current"] == OLD_VERSION, rolled
        final = bootstrap(install_root, bin_dir, "install", str(new_wheel))
        assert final["current"] == CURRENT_VERSION, final

        launcher = Path(final["launcher"])
        if not launcher.exists():
            raise RuntimeError("launcher was not created")
        # Doctor does not require workspace trust and proves the switched release launches.
        if os.name == "nt":
            run("cmd.exe", "/d", "/c", str(launcher), "doctor", "--workspace", str(ROOT))
        else:
            run(str(launcher), "doctor", "--workspace", str(ROOT))

        status = bootstrap(install_root, bin_dir, "status")
        assert status["current"] == CURRENT_VERSION, status
        print(json.dumps({"ok": True, "current": status["current"], "history": status["history"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
