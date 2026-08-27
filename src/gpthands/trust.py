from __future__ import annotations

import hashlib
import time
from pathlib import Path

from .state import read_json_object, secure_write_json, state_root


class TrustError(RuntimeError):
    pass


def _workspace_key(workspace: Path) -> tuple[str, str]:
    resolved = workspace.expanduser().resolve(strict=True)
    if not resolved.is_dir():
        raise TrustError("workspace must be a directory")
    text = str(resolved)
    return hashlib.sha256(text.encode("utf-8")).hexdigest(), text


class WorkspaceTrustStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (state_root() / "workspace-trust.json")

    def _load(self) -> dict:
        data = read_json_object(self.path)
        if not data:
            return {"version": 1, "workspaces": {}}
        if data.get("version") != 1 or not isinstance(data.get("workspaces"), dict):
            raise TrustError("unsupported workspace trust store format")
        return data

    def trust(self, workspace: Path, *, label: str | None = None) -> dict:
        key, canonical = _workspace_key(workspace)
        data = self._load()
        record = {
            "path": canonical,
            "trusted_at": int(time.time()),
            "label": (label or Path(canonical).name)[:120],
        }
        data["workspaces"][key] = record
        secure_write_json(self.path, data)
        return record

    def untrust(self, workspace: Path) -> bool:
        key, _ = _workspace_key(workspace)
        data = self._load()
        existed = data["workspaces"].pop(key, None) is not None
        if existed:
            secure_write_json(self.path, data)
        return existed

    def is_trusted(self, workspace: Path) -> bool:
        key, canonical = _workspace_key(workspace)
        record = self._load()["workspaces"].get(key)
        return isinstance(record, dict) and record.get("path") == canonical

    def list(self) -> list[dict]:
        rows = []
        for key, value in self._load()["workspaces"].items():
            if isinstance(value, dict):
                rows.append({"id": key, **value})
        return sorted(rows, key=lambda row: (str(row.get("label", "")).lower(), str(row.get("path", ""))))
