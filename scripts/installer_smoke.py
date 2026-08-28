#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "scripts" / "release_bootstrap.py"
CURRENT_VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
OLD_VERSION = "0.9.999"


def run(*argv: str, cwd: Path = ROOT) -> str:
    completed = subprocess.run(
        list(argv), cwd=cwd, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, shell=False, timeout=240, check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(argv)}\n"
            f"stdout={completed.stdout!r}\nstderr={completed.stderr!r}"
        )
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


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def bootstrap(root: Path, bin_dir: Path, *args: str) -> dict:
    argv = (sys.executable, str(BOOTSTRAP), "--root", str(root), "--bin-dir", str(bin_dir), *args)
    completed = subprocess.run(
        list(argv), cwd=ROOT, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, shell=False, timeout=240, check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"bootstrap failed ({completed.returncode}): {' '.join(argv)}\n"
            f"stdout={completed.stdout!r}\nstderr={completed.stderr!r}"
        )
    if not completed.stdout.strip():
        raise RuntimeError(
            f"bootstrap returned success with empty stdout: {' '.join(argv)}\n"
            f"stderr={completed.stderr!r}"
        )
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"bootstrap returned non-JSON stdout: {completed.stdout!r}; stderr={completed.stderr!r}"
        ) from exc


def install_args(wheel: Path) -> tuple[str, ...]:
    return ("install", str(wheel), "--sha256", digest(wheel))


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

        first = bootstrap(install_root, bin_dir, *install_args(old_wheel))
        assert first["current"] == OLD_VERSION, first
        assert first["digests"][OLD_VERSION] == digest(old_wheel), first

        second = bootstrap(install_root, bin_dir, *install_args(new_wheel))
        assert second["current"] == CURRENT_VERSION and OLD_VERSION in second["history"], second
        assert second["digests"][CURRENT_VERSION] == digest(new_wheel), second

        rolled = bootstrap(install_root, bin_dir, "rollback")
        assert rolled["current"] == OLD_VERSION, rolled

        final = bootstrap(install_root, bin_dir, *install_args(new_wheel))
        assert final["current"] == CURRENT_VERSION, final

        launcher = Path(final["launcher"])
        if not launcher.exists():
            raise RuntimeError("launcher was not created")
        if os.name == "nt":
            run("cmd.exe", "/d", "/c", str(launcher), "doctor", "--workspace", str(ROOT))
        else:
            run(str(launcher), "doctor", "--workspace", str(ROOT))

        status = bootstrap(install_root, bin_dir, "status")
        assert status["current"] == CURRENT_VERSION, status
        print(json.dumps({
            "ok": True,
            "current": status["current"],
            "history": status["history"],
            "digest_bound_versions": sorted(status["digests"]),
        }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())