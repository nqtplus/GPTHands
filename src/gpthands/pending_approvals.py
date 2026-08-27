from __future__ import annotations

import time
from pathlib import Path

from .approval import workspace_id
from .locking import FileLock, LockError
from .state import read_json_object, secure_write_json, state_root


class PendingApprovalError(RuntimeError):
    pass


class PendingApprovalStore:
    """Small external metadata queue; never stores command arguments, file content, tokens, or secrets."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (state_root() / "pending-approvals.json")
        self._lock = FileLock(self.path.with_name(self.path.name + ".lock"))

    def close(self) -> None:
        self._lock.close()

    def _load(self) -> dict:
        data = read_json_object(self.path)
        if not data:
            return {"version": 1, "requests": {}}
        if data.get("version") != 1 or not isinstance(data.get("requests"), dict):
            raise PendingApprovalError("pending approval store format is invalid")
        return data

    @staticmethod
    def _key(workspace: Path, action_hash: str) -> str:
        if len(action_hash) != 64 or any(ch not in "0123456789abcdef" for ch in action_hash):
            raise PendingApprovalError("action hash is invalid")
        return f"{workspace_id(workspace)}:{action_hash}"

    def add(self, *, workspace: Path, risk: str, action_hash: str) -> dict:
        key = self._key(workspace, action_hash)
        resolved = workspace.resolve(strict=True)
        try:
            with self._lock:
                data = self._load()
                existing = data["requests"].get(key)
                created_at = int(existing.get("created_at", time.time())) if isinstance(existing, dict) else int(time.time())
                record = {
                    "workspace": str(resolved),
                    "workspace_id": workspace_id(resolved),
                    "risk": str(risk),
                    "action_hash": action_hash,
                    "created_at": created_at,
                    "last_seen_at": int(time.time()),
                }
                data["requests"][key] = record
                secure_write_json(self.path, data)
                return record
        except LockError as exc:
            raise PendingApprovalError(str(exc)) from exc

    def remove(self, *, workspace: Path, action_hash: str) -> bool:
        key = self._key(workspace, action_hash)
        try:
            with self._lock:
                data = self._load()
                existed = data["requests"].pop(key, None) is not None
                if existed:
                    secure_write_json(self.path, data)
                return existed
        except LockError as exc:
            raise PendingApprovalError(str(exc)) from exc

    def list_for_workspace(self, workspace: Path, *, max_age_seconds: int = 3600) -> list[dict]:
        resolved = workspace.resolve(strict=True)
        wid = workspace_id(resolved)
        cutoff = int(time.time()) - max_age_seconds
        try:
            with self._lock:
                data = self._load()
                changed = False
                rows: list[dict] = []
                for key, value in list(data["requests"].items()):
                    if not isinstance(value, dict) or int(value.get("last_seen_at", 0)) < cutoff:
                        data["requests"].pop(key, None)
                        changed = True
                        continue
                    if value.get("workspace_id") == wid and value.get("workspace") == str(resolved):
                        rows.append(dict(value))
                if changed:
                    secure_write_json(self.path, data)
                return sorted(rows, key=lambda row: int(row.get("created_at", 0)), reverse=True)
        except LockError as exc:
            raise PendingApprovalError(str(exc)) from exc
