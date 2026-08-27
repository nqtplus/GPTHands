from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_SECRET_VALUE_PATTERNS = (
    re.compile(r"sk-[A-Za-z0-9_-]{12,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)


def redact_text(value: str) -> str:
    result = value
    for pattern in _SECRET_VALUE_PATTERNS:
        result = pattern.sub("[REDACTED]", result)
    return result


def content_fingerprint(value: str) -> dict[str, Any]:
    data = value.encode("utf-8", errors="replace")
    return {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


class AuditLogger:
    """Append-only audit sink held open with no-follow semantics when supported."""

    def __init__(self, path: Path, *, workspace: Path | None = None) -> None:
        self.path = path.expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)

        if self.path.is_symlink():
            raise OSError("audit log must not be a symlink")

        resolved = self.path.resolve(strict=False)
        if workspace is not None:
            root = workspace.expanduser().resolve(strict=True)
            try:
                common = Path(os.path.commonpath((str(root), str(resolved))))
            except ValueError as exc:
                raise OSError("invalid audit log path") from exc
            if common == root:
                raise OSError("audit log must be outside the MCP workspace")

        flags = os.O_CREAT | os.O_WRONLY | os.O_APPEND
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        self._fd = os.open(self.path, flags, 0o600)
        info = os.fstat(self._fd)
        if not stat.S_ISREG(info.st_mode):
            os.close(self._fd)
            raise OSError("audit log must be a regular file")
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            os.close(self._fd)
            raise OSError("audit log must be owned by the current user")
        if os.name != "nt":
            os.fchmod(self._fd, 0o600)

    def close(self) -> None:
        fd = getattr(self, "_fd", None)
        if fd is not None:
            os.close(fd)
            self._fd = None

    def __del__(self) -> None:
        try:
            self.close()
        except OSError:
            pass

    def record(
        self,
        *,
        request_id: Any,
        tool: str,
        outcome: str,
        detail: dict[str, Any] | None = None,
    ) -> None:
        event = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "request_id": request_id,
            "tool": tool,
            "outcome": outcome,
            "detail": detail or {},
        }
        encoded = redact_text(json.dumps(event, ensure_ascii=False, sort_keys=True)).encode("utf-8") + b"\n"
        if self._fd is None:
            raise OSError("audit log is closed")
        os.write(self._fd, encoded)
