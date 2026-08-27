from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO

from .locking import FileLock, LockError


_SECRET_VALUE_PATTERNS = (
    re.compile(r"sk-[A-Za-z0-9_-]{12,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)
_AUDIT_CHAIN_VERSION = 1
_GENESIS_HASH = "0" * 64
_MAX_TAIL_RECORD_BYTES = 1_048_576


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


@dataclass(frozen=True)
class AuditVerification:
    valid: bool
    chained_records: int
    legacy_records: int
    anchored: bool
    last_hash: str | None = None
    error: str | None = None


def _canonical_event(event: dict[str, Any]) -> bytes:
    clone = json.loads(json.dumps(event, ensure_ascii=False))
    audit = clone.get("audit")
    if isinstance(audit, dict):
        audit.pop("hash", None)
    return json.dumps(clone, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _event_hash(event: dict[str, Any], prev_hash: str) -> str:
    payload = prev_hash.encode("ascii") + b"\n" + _canonical_event(event)
    return hashlib.sha256(payload).hexdigest()


def _verify_stream(handle: BinaryIO) -> AuditVerification:
    handle.seek(0)
    previous = _GENESIS_HASH
    expected_seq = 1
    chained = 0
    legacy = 0
    legacy_hasher = hashlib.sha256()
    chain_started = False

    for raw_line in handle:
        if not raw_line.strip():
            continue
        try:
            event = json.loads(raw_line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return AuditVerification(False, chained, legacy, chain_started, previous if chained else None, f"invalid JSONL: {exc}")

        audit = event.get("audit") if isinstance(event, dict) else None
        if not isinstance(audit, dict) or audit.get("v") != _AUDIT_CHAIN_VERSION:
            if chain_started:
                return AuditVerification(False, chained, legacy, True, previous, "legacy/unversioned record appears after hash chain started")
            legacy += 1
            legacy_hasher.update(raw_line)
            continue

        if not chain_started:
            chain_started = True
            previous = legacy_hasher.hexdigest() if legacy else _GENESIS_HASH

        try:
            seq = int(audit.get("seq"))
            prev_hash = str(audit.get("prev_hash"))
            supplied = str(audit.get("hash"))
        except (TypeError, ValueError):
            return AuditVerification(False, chained, legacy, True, previous, "invalid audit chain metadata")

        if seq != expected_seq:
            return AuditVerification(False, chained, legacy, True, previous, f"audit sequence mismatch: expected {expected_seq}, got {seq}")
        if prev_hash != previous:
            return AuditVerification(False, chained, legacy, True, previous, "audit previous-hash mismatch")
        expected = _event_hash(event, previous)
        if supplied != expected:
            return AuditVerification(False, chained, legacy, True, previous, "audit record hash mismatch")
        previous = supplied
        expected_seq += 1
        chained += 1

    return AuditVerification(True, chained, legacy, chain_started, previous if chained else None, None)


def verify_audit_file(path: Path) -> AuditVerification:
    target = path.expanduser()
    if target.is_symlink():
        return AuditVerification(False, 0, 0, False, error="audit log must not be a symlink")
    if not target.exists():
        return AuditVerification(True, 0, 0, False)
    try:
        with FileLock(target.with_name(target.name + ".lock")):
            with target.open("rb") as handle:
                return _verify_stream(handle)
    except (OSError, LockError) as exc:
        return AuditVerification(False, 0, 0, False, error=str(exc))


class AuditLogger:
    """Locked append-only audit sink with a SHA-256 hash chain."""

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

        flags = os.O_CREAT | os.O_RDWR | os.O_APPEND
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

        self._lock = FileLock(self.path.with_name(self.path.name + ".lock"))
        with self._lock:
            verification = self._verify_locked()
            if not verification.valid:
                self.close()
                raise OSError(f"audit chain verification failed: {verification.error}")

    def _verify_locked(self) -> AuditVerification:
        duplicate = os.dup(self._fd)
        try:
            with os.fdopen(duplicate, "rb", closefd=True) as handle:
                return _verify_stream(handle)
        except Exception:
            try:
                os.close(duplicate)
            except OSError:
                pass
            raise

    def close(self) -> None:
        lock = getattr(self, "_lock", None)
        if lock is not None:
            lock.close()
            self._lock = None
        fd = getattr(self, "_fd", None)
        if fd is not None:
            os.close(fd)
            self._fd = None

    def __del__(self) -> None:
        try:
            self.close()
        except (OSError, LockError):
            pass

    def _last_nonempty_line_locked(self) -> bytes | None:
        with self.path.open("rb") as handle:
            size = handle.seek(0, os.SEEK_END)
            if size == 0:
                return None
            length = min(size, _MAX_TAIL_RECORD_BYTES)
            handle.seek(size - length)
            tail = handle.read(length)
        rows = [row for row in tail.splitlines() if row.strip()]
        if not rows:
            return None
        if size > _MAX_TAIL_RECORD_BYTES and len(rows) == 1:
            raise OSError("last audit record exceeds maximum supported tail size")
        return rows[-1]

    def _chain_state_locked(self) -> tuple[int, str]:
        last_line = self._last_nonempty_line_locked()
        if last_line is None:
            return 1, _GENESIS_HASH

        try:
            event = json.loads(last_line.decode("utf-8"))
            audit = event.get("audit") if isinstance(event, dict) else None
            if isinstance(audit, dict) and audit.get("v") == _AUDIT_CHAIN_VERSION:
                seq = int(audit.get("seq"))
                prev_hash = str(audit.get("prev_hash"))
                supplied = str(audit.get("hash"))
                if len(supplied) != 64 or supplied != _event_hash(event, prev_hash):
                    raise OSError("last audit record hash is invalid")
                return seq + 1, supplied
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise OSError("last audit record is malformed") from exc

        # Only a pure v0.1/v0.2 prefix may end in an unchained record. Verify
        # the entire file once, then anchor the exact legacy bytes. Chained logs
        # never need a full scan on every append, so steady-state recording is
        # O(1) in log length while explicit verification remains O(n).
        verification = self._verify_locked()
        if not verification.valid or verification.chained_records:
            raise OSError(f"audit chain verification failed: {verification.error or 'unexpected legacy tail'}")
        with self.path.open("rb") as handle:
            legacy_bytes = handle.read()
        previous = hashlib.sha256(legacy_bytes).hexdigest() if legacy_bytes else _GENESIS_HASH
        return 1, previous

    def record(
        self,
        *,
        request_id: Any,
        tool: str,
        outcome: str,
        detail: dict[str, Any] | None = None,
    ) -> None:
        if self._fd is None or self._lock is None:
            raise OSError("audit log is closed")
        with self._lock:
            seq, previous = self._chain_state_locked()
            event: dict[str, Any] = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "request_id": request_id,
                "tool": tool,
                "outcome": outcome,
                "detail": detail or {},
                "audit": {
                    "v": _AUDIT_CHAIN_VERSION,
                    "seq": seq,
                    "prev_hash": previous,
                },
            }
            # Redact before hashing so verification covers exactly the durable
            # bytes rather than pre-redaction sensitive data.
            sanitized = json.loads(redact_text(json.dumps(event, ensure_ascii=False)))
            sanitized["audit"]["hash"] = _event_hash(sanitized, previous)
            encoded = (json.dumps(sanitized, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
            os.write(self._fd, encoded)
            os.fsync(self._fd)
