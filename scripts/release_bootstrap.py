#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import venv
import zipfile
from email.parser import BytesParser
from pathlib import Path


class BootstrapError(RuntimeError):
    pass


def default_root() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return base / "GPTHands"
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "gpthands"


def default_bin_dir() -> Path:
    if os.name == "nt":
        return default_root() / "bin"
    return Path.home() / ".local" / "bin"


def inspect_wheel(wheel: Path) -> tuple[str, str]:
    wheel = wheel.expanduser().resolve(strict=True)
    if wheel.suffix != ".whl":
        raise BootstrapError("installer input must be a .whl file")
    with zipfile.ZipFile(wheel) as archive:
        metadata_names = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        if len(metadata_names) != 1:
            raise BootstrapError("wheel must contain exactly one dist-info/METADATA")
        message = BytesParser().parsebytes(archive.read(metadata_names[0]))
    name = str(message.get("Name", "")).strip().lower()
    version = str(message.get("Version", "")).strip()
    if name != "gpthands" or not version or any(ch not in "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-_+" for ch in version):
        raise BootstrapError("wheel metadata is not a valid GPTHands release")
    return name, version


def _python_in(release: Path) -> Path:
    return release / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def _launcher_path(bin_dir: Path) -> Path:
    return bin_dir / ("gpthands.cmd" if os.name == "nt" else "gpthands")


def _launcher_text(python: Path) -> str:
    if os.name == "nt":
        return f'@echo off\r\n"{python}" -m gpthands.cli %*\r\n'
    quoted = "'" + str(python).replace("'", "'\\''") + "'"
    return f"#!/bin/sh\nexec {quoted} -m gpthands.cli \"$@\"\n"


def _secure_atomic_text(path: Path, text: str, *, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or path.parent.is_symlink():
        raise BootstrapError(f"refusing symlink install path: {path}")
    fd, temp_name = tempfile.mkstemp(prefix=".gpthands-install-", dir=path.parent)
    try:
        if os.name != "nt":
            os.fchmod(fd, 0o700 if executable else 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
        if os.name != "nt":
            os.chmod(path, 0o700 if executable else 0o600)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def _load_manifest(path: Path) -> dict:
    if not path.exists():
        return {"schema": 1, "current": None, "history": []}
    if path.is_symlink():
        raise BootstrapError("install manifest must not be a symlink")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BootstrapError(f"invalid install manifest: {exc}") from exc
    if data.get("schema") != 1 or not isinstance(data.get("history"), list):
        raise BootstrapError("unsupported install manifest")
    return data


def _write_manifest(path: Path, data: dict) -> None:
    _secure_atomic_text(path, json.dumps(data, indent=2, sort_keys=True) + "\n")


def _smoke_release(release: Path, expected_version: str) -> None:
    python = _python_in(release)
    code = (
        "import importlib.metadata, gpthands; "
        f"assert importlib.metadata.version('gpthands') == {expected_version!r}; "
        "print(importlib.metadata.version('gpthands'))"
    )
    completed = subprocess.run(
        [str(python), "-c", code],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        shell=False,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        raise BootstrapError(f"installed release smoke test failed: {completed.stdout[-1000:]}")


def install(wheel: Path, *, root: Path, bin_dir: Path) -> dict:
    _, version = inspect_wheel(wheel)
    root = root.expanduser().resolve(strict=False)
    bin_dir = bin_dir.expanduser().resolve(strict=False)
    if root.is_symlink() or bin_dir.is_symlink():
        raise BootstrapError("install root/bin directory must not be a symlink")
    releases = root / "releases"
    releases.mkdir(parents=True, exist_ok=True)
    target = releases / version
    manifest_path = root / "install-state.json"
    manifest = _load_manifest(manifest_path)

    if not target.exists():
        target.mkdir(parents=False)
        try:
            venv.EnvBuilder(with_pip=True, clear=False, symlinks=False).create(target)
            python = _python_in(target)
            completed = subprocess.run(
                [str(python), "-m", "pip", "install", "--disable-pip-version-check", "--no-index", "--no-deps", str(wheel.resolve(strict=True))],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                shell=False,
                timeout=180,
                check=False,
            )
            if completed.returncode != 0:
                raise BootstrapError(f"offline wheel install failed: {completed.stdout[-1500:]}")
            _smoke_release(target, version)
        except Exception:
            shutil.rmtree(target, ignore_errors=True)
            raise
    else:
        _smoke_release(target, version)

    current = manifest.get("current")
    history = [str(item) for item in manifest.get("history", []) if isinstance(item, str)]
    if current and current != version:
        history = [item for item in history if item != current]
        history.append(str(current))
    history = history[-10:]

    launcher = _launcher_path(bin_dir)
    _secure_atomic_text(launcher, _launcher_text(_python_in(target)), executable=True)
    manifest = {"schema": 1, "current": version, "history": history, "launcher": str(launcher)}
    _write_manifest(manifest_path, manifest)
    return manifest


def rollback(*, root: Path, bin_dir: Path) -> dict:
    root = root.expanduser().resolve(strict=True)
    manifest_path = root / "install-state.json"
    manifest = _load_manifest(manifest_path)
    history = [str(item) for item in manifest.get("history", []) if isinstance(item, str)]
    if not history:
        raise BootstrapError("no previous GPTHands release is available for rollback")
    previous = history.pop()
    target = root / "releases" / previous
    if not target.exists():
        raise BootstrapError(f"rollback release is missing: {previous}")
    _smoke_release(target, previous)
    current = manifest.get("current")
    launcher = _launcher_path(bin_dir.expanduser().resolve(strict=False))
    _secure_atomic_text(launcher, _launcher_text(_python_in(target)), executable=True)
    if isinstance(current, str) and current != previous:
        history.insert(0, current)
        history = history[-10:]
    updated = {"schema": 1, "current": previous, "history": history, "launcher": str(launcher)}
    _write_manifest(manifest_path, updated)
    return updated


def status(*, root: Path) -> dict:
    root = root.expanduser().resolve(strict=False)
    return _load_manifest(root / "install-state.json")


def uninstall(*, root: Path, bin_dir: Path) -> dict:
    root = root.expanduser().resolve(strict=False)
    launcher = _launcher_path(bin_dir.expanduser().resolve(strict=False))
    removed = False
    if launcher.exists():
        if launcher.is_symlink():
            raise BootstrapError("refusing to remove symlink launcher")
        launcher.unlink()
        removed = True
    manifest = root / "install-state.json"
    if manifest.exists() and not manifest.is_symlink():
        manifest.unlink()
    return {"launcher_removed": removed, "releases_preserved": str(root / "releases")}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="GPTHands offline release bootstrap/rollback installer")
    parser.add_argument("--root", type=Path, default=default_root())
    parser.add_argument("--bin-dir", type=Path, default=default_bin_dir())
    sub = parser.add_subparsers(dest="command", required=True)
    install_p = sub.add_parser("install")
    install_p.add_argument("wheel", type=Path)
    sub.add_parser("rollback")
    sub.add_parser("status")
    sub.add_parser("uninstall")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "install":
            result = install(args.wheel, root=args.root, bin_dir=args.bin_dir)
        elif args.command == "rollback":
            result = rollback(root=args.root, bin_dir=args.bin_dir)
        elif args.command == "status":
            result = status(root=args.root)
        else:
            result = uninstall(root=args.root, bin_dir=args.bin_dir)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (BootstrapError, OSError, subprocess.SubprocessError, zipfile.BadZipFile) as exc:
        print(f"GPTHands installer refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
