from __future__ import annotations

import json
import os
import shutil
import stat
import sys
import time
from pathlib import Path

from .state import secure_write_json, secure_write_text, state_root


class InstallError(RuntimeError):
    pass


def default_bin_dir() -> Path:
    if os.name == "nt":
        return state_root().parent / "bin"
    return Path.home() / ".local" / "bin"


def _wrapper_text(kind: str) -> str:
    if kind not in {"ui", "doctor"}:
        raise InstallError("unknown launcher kind")
    args = "ui" if kind == "ui" else "doctor"
    if os.name == "nt":
        return f'@echo off\r\n"{sys.executable}" -m gpthands.cli {args} %*\r\n'
    return f'#!/bin/sh\nexec {sh_quote(sys.executable)} -m gpthands.cli {args} "$@"\n'


def sh_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


class UserInstaller:
    def __init__(self, *, bin_dir: Path | None = None, manifest: Path | None = None) -> None:
        self.bin_dir = (bin_dir or default_bin_dir()).expanduser()
        self.manifest = manifest or (state_root() / "install-manifest.json")

    def _targets(self) -> dict[str, Path]:
        suffix = ".cmd" if os.name == "nt" else ""
        return {
            "ui": self.bin_dir / f"gpthands-ui{suffix}",
            "doctor": self.bin_dir / f"gpthands-doctor{suffix}",
        }

    def install(self) -> dict:
        self.bin_dir.mkdir(parents=True, exist_ok=True)
        if self.bin_dir.is_symlink():
            raise InstallError("bin directory must not be a symlink")
        stamp = int(time.time())
        records: dict[str, dict] = {}
        for kind, target in self._targets().items():
            if target.is_symlink():
                raise InstallError(f"refusing to replace symlink launcher: {target}")
            backup = None
            if target.exists():
                backup = target.with_name(f"{target.name}.gpthands-backup-{stamp}")
                if backup.exists():
                    raise InstallError(f"backup path already exists: {backup}")
                shutil.copy2(target, backup)
            secure_write_text(target, _wrapper_text(kind))
            if os.name != "nt":
                os.chmod(target, 0o700)
            records[kind] = {"target": str(target), "backup": str(backup) if backup else None}
        payload = {"version": 1, "installed_at": stamp, "records": records}
        secure_write_json(self.manifest, payload)
        return payload

    def uninstall(self) -> dict:
        if not self.manifest.exists():
            return {"removed": [], "restored": []}
        data = json.loads(self.manifest.read_text(encoding="utf-8"))
        if data.get("version") != 1 or not isinstance(data.get("records"), dict):
            raise InstallError("install manifest is invalid")
        removed: list[str] = []
        restored: list[str] = []
        for record in data["records"].values():
            if not isinstance(record, dict):
                continue
            target = Path(str(record.get("target", "")))
            backup_value = record.get("backup")
            backup = Path(backup_value) if isinstance(backup_value, str) and backup_value else None
            if target.exists() and not target.is_symlink():
                target.unlink()
                removed.append(str(target))
            if backup and backup.exists() and not backup.is_symlink():
                os.replace(backup, target)
                restored.append(str(target))
        self.manifest.unlink(missing_ok=True)
        return {"removed": removed, "restored": restored}
