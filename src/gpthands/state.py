from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


class StateError(RuntimeError):
    pass


def state_root() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return base / "GPTHands" / "State"
    if sys_platform() == "darwin":
        return Path.home() / "Library" / "Application Support" / "GPTHands"
    return Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")) / "gpthands"


def sys_platform() -> str:
    import sys
    return sys.platform


def ensure_private_dir(path: Path) -> Path:
    path = path.expanduser()
    if path.is_symlink():
        raise StateError("state directory must not be a symlink")
    path.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(path, 0o700)
    return path


def secure_write_text(path: Path, text: str) -> None:
    path = path.expanduser()
    parent = ensure_private_dir(path.parent)
    if path.is_symlink():
        raise StateError("refusing to replace a symlink state file")
    fd, tmp = tempfile.mkstemp(prefix=".gpthands-", dir=parent)
    try:
        if os.name != "nt":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        if os.name != "nt":
            os.chmod(path, 0o600)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def secure_write_json(path: Path, value: Any) -> None:
    secure_write_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def read_json_object(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    if path.is_symlink() or not path.is_file():
        raise StateError("state file must be a regular non-symlink file")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise StateError("state file root must be an object")
    return raw
