from __future__ import annotations

import hashlib
import json
import os
import re
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
    def __init__(self, path: Path) -> None:
        self.path = path.expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            fd = os.open(self.path, os.O_CREAT | os.O_WRONLY, 0o600)
            os.close(fd)
        else:
            try:
                os.chmod(self.path, 0o600)
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
        encoded = redact_text(json.dumps(event, ensure_ascii=False, sort_keys=True))
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(encoded + "\n")
