#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
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


_SHA256_HEX = frozenset("0123456789abcdef")
_RELEASE_INFO = ".gpthands-release.json"


def default_root() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return base / "GPTHands"
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "gpthands"


def default_bin_dir() -> Path:
    if os.name == "nt":
        return default_root() / "bin"
    return Path.home() / ".local" / "bin"


def _lexical_absolute(path: Path) -> Path:
    """Make a path absolute without resolving away a final symlink."""

    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _refuse_symlink(path: Path, label: str) -> None:
    if path.is_symlink():
        raise BootstrapError(f"{label} must not be a symlink: {path}")


def _normalize_sha256(value: str) -> str:
    digest = value.strip().lower()
    if len(digest) != 64 or any(ch not in _SHA256_HEX for ch in digest):
        raise BootstrapError("expected wheel SHA-256 must be exactly 64 hexadecimal characters")
    return digest


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_wheel_sha256(wheel: Path, expected_sha256: str) -> str:
    wheel = _lexical_absolute(wheel)
    _refuse_symlink(wheel, "wheel")
    if not wheel.is_file():
        raise BootstrapError(f"wheel does not exist or is not a regular file: {wheel}")
    expected = _normalize_sha256(expected_sha256)
    actual = sha256_file(wheel)
    if not hmac.compare_digest(actual, expected):
        raise BootstrapError(f"wheel SHA-256 mismatch: expected {expected}, got {actual}")
    return actual


def inspect_wheel(wheel: Path) -> tuple[str, str]:
    wheel = _lexical_absolute(wheel)
    _refuse_symlink(wheel, "wheel")
    if not wheel.is_file():
        raise BootstrapError("installer input must be a regular .whl file")
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
    path = _lexical_absolute(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _refuse_symlink(path, "managed file")
    _refuse_symlink(path.parent, "managed parent directory")
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
    path = _lexical_absolute(path)
    if not path.exists():
        return {"schema": 1, "current": None, "history": [], "digests": {}}
    _refuse_symlink(path, "install manifest")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BootstrapError(f"invalid install manifest: {exc}") from exc
    if data.get("schema") != 1 or not isinstance(data.get("history"), list):
        raise BootstrapError("unsupported install manifest")
    digests = data.get("digests", {})
    if not isinstance(digests, dict):
        raise BootstrapError("install manifest digests must be an object")
    for version, digest in digests.items():
        if not isinstance(version, str) or not isinstance(digest, str):
            raise BootstrapError("install manifest digest entries must be strings")
        _normalize_sha256(digest)
    data["digests"] = digests
    return data


def _write_manifest(path: Path, data: dict) -> None:
    _secure_atomic_text(path, json.dumps(data, indent=2, sort_keys=True) + "\n")


def _release_info_path(release: Path) -> Path:
    return release / _RELEASE_INFO


def _write_release_info(release: Path, *, version: str, wheel_sha256: str) -> None:
    payload = {
        "schema": 1,
        "version": version,
        "wheel_sha256": _normalize_sha256(wheel_sha256),
    }
    _secure_atomic_text(_release_info_path(release), json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _load_release_info(release: Path, *, expected_version: str, expected_sha256: str) -> dict:
    release = _lexical_absolute(release)
    _refuse_symlink(release, "release directory")
    if not release.is_dir():
        raise BootstrapError(f"release directory is missing: {release}")
    marker = _release_info_path(release)
    _refuse_symlink(marker, "release integrity marker")
    if not marker.is_file():
        raise BootstrapError(f"release integrity marker is missing: {marker}")
    try:
        data = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BootstrapError(f"invalid release integrity marker: {exc}") from exc
    if data.get("schema") != 1 or data.get("version") != expected_version:
        raise BootstrapError("release integrity marker version mismatch")
    marker_digest = data.get("wheel_sha256")
    if not isinstance(marker_digest, str):
        raise BootstrapError("release integrity marker is missing wheel_sha256")
    marker_digest = _normalize_sha256(marker_digest)
    expected = _normalize_sha256(expected_sha256)
    if not hmac.compare_digest(marker_digest, expected):
        raise BootstrapError("installed release is bound to a different wheel digest")
    return data


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


def install(wheel: Path, *, expected_sha256: str, root: Path, bin_dir: Path) -> dict:
    wheel = _lexical_absolute(wheel)
    digest = verify_wheel_sha256(wheel, expected_sha256)
    _, version = inspect_wheel(wheel)

    root = _lexical_absolute(root)
    bin_dir = _lexical_absolute(bin_dir)
    _refuse_symlink(root, "install root")
    _refuse_symlink(bin_dir, "bin directory")
    root.mkdir(parents=True, exist_ok=True)
    bin_dir.mkdir(parents=True, exist_ok=True)
    _refuse_symlink(root, "install root")
    _refuse_symlink(bin_dir, "bin directory")

    releases = root / "releases"
    _refuse_symlink(releases, "releases directory")
    releases.mkdir(parents=True, exist_ok=True)
    _refuse_symlink(releases, "releases directory")

    target = releases / version
    _refuse_symlink(target, "release target")
    manifest_path = root / "install-state.json"
    manifest = _load_manifest(manifest_path)
    digests = {str(k): str(v) for k, v in manifest.get("digests", {}).items()}
    recorded = digests.get(version)
    if recorded is not None and not hmac.compare_digest(_normalize_sha256(recorded), digest):
        raise BootstrapError("manifest already binds this version to a different wheel digest")

    if not target.exists():
        target.mkdir(parents=False)
        _refuse_symlink(target, "release target")
        try:
            venv.EnvBuilder(with_pip=True, clear=False, symlinks=False).create(target)
            python = _python_in(target)
            completed = subprocess.run(
                [str(python), "-m", "pip", "install", "--disable-pip-version-check", "--no-index", "--no-deps", str(wheel)],
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
            _write_release_info(target, version=version, wheel_sha256=digest)
        except Exception:
            shutil.rmtree(target, ignore_errors=True)
            raise
    else:
        _load_release_info(target, expected_version=version, expected_sha256=digest)
        _smoke_release(target, version)

    current = manifest.get("current")
    history = [str(item) for item in manifest.get("history", []) if isinstance(item, str)]
    if current and current != version:
        history = [item for item in history if item != current]
        history.append(str(current))
    history = history[-10:]
    digests[version] = digest

    launcher = _launcher_path(bin_dir)
    _secure_atomic_text(launcher, _launcher_text(_python_in(target)), executable=True)
    manifest = {
        "schema": 1,
        "current": version,
        "history": history,
        "digests": dict(sorted(digests.items())),
        "launcher": str(launcher),
    }
    _write_manifest(manifest_path, manifest)
    return manifest


def rollback(*, root: Path, bin_dir: Path) -> dict:
    root = _lexical_absolute(root)
    bin_dir = _lexical_absolute(bin_dir)
    if not root.exists():
        raise BootstrapError(f"install root is missing: {root}")
    _refuse_symlink(root, "install root")
    _refuse_symlink(bin_dir, "bin directory")
    manifest_path = root / "install-state.json"
    manifest = _load_manifest(manifest_path)
    history = [str(item) for item in manifest.get("history", []) if isinstance(item, str)]
    if not history:
        raise BootstrapError("no previous GPTHands release is available for rollback")
    previous = history.pop()
    releases = root / "releases"
    _refuse_symlink(releases, "releases directory")
    target = releases / previous
    _refuse_symlink(target, "rollback release")
    digests = manifest.get("digests", {})
    expected_digest = digests.get(previous) if isinstance(digests, dict) else None
    if not isinstance(expected_digest, str):
        raise BootstrapError(f"rollback release has no recorded wheel digest: {previous}")
    _load_release_info(target, expected_version=previous, expected_sha256=expected_digest)
    _smoke_release(target, previous)

    current = manifest.get("current")
    launcher = _launcher_path(bin_dir)
    _secure_atomic_text(launcher, _launcher_text(_python_in(target)), executable=True)
    if isinstance(current, str) and current != previous:
        history.insert(0, current)
        history = history[-10:]
    updated = {
        "schema": 1,
        "current": previous,
        "history": history,
        "digests": dict(sorted({str(k): str(v) for k, v in digests.items()}.items())),
        "launcher": str(launcher),
    }
    _write_manifest(manifest_path, updated)
    return updated


def status(*, root: Path) -> dict:
    root = _lexical_absolute(root)
    _refuse_symlink(root, "install root")
    return _load_manifest(root / "install-state.json")


def uninstall(*, root: Path, bin_dir: Path) -> dict:
    root = _lexical_absolute(root)
    bin_dir = _lexical_absolute(bin_dir)
    _refuse_symlink(root, "install root")
    _refuse_symlink(bin_dir, "bin directory")
    launcher = _launcher_path(bin_dir)
    removed = False
    if launcher.exists() or launcher.is_symlink():
        _refuse_symlink(launcher, "launcher")
        launcher.unlink()
        removed = True
    manifest = root / "install-state.json"
    if manifest.is_symlink():
        raise BootstrapError("refusing symlink install manifest")
    if manifest.exists():
        manifest.unlink()
    return {"launcher_removed": removed, "releases_preserved": str(root / "releases")}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="GPTHands offline release bootstrap/rollback installer")
    parser.add_argument("--root", type=Path, default=default_root())
    parser.add_argument("--bin-dir", type=Path, default=default_bin_dir())
    sub = parser.add_subparsers(dest="command", required=True)
    install_p = sub.add_parser("install")
    install_p.add_argument("wheel", type=Path)
    install_p.add_argument("--sha256", required=True, help="trusted expected SHA-256 for the wheel")
    sub.add_parser("rollback")
    sub.add_parser("status")
    sub.add_parser("uninstall")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "install":
            result = install(
                args.wheel,
                expected_sha256=args.sha256,
                root=args.root,
                bin_dir=args.bin_dir,
            )
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
