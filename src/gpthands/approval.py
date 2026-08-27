from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import stat
import time
from pathlib import Path
from typing import Any

from .locking import FileLock, LockError
from .risk import RiskLevel


class ApprovalError(RuntimeError):
    pass


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def workspace_id(workspace: Path) -> str:
    return hashlib.sha256(str(workspace.resolve(strict=True)).encode("utf-8")).hexdigest()


class ApprovalManager:
    def __init__(self, key_path: Path, used_path: Path | None = None) -> None:
        lexical = key_path.expanduser()
        lexical.parent.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            try:
                os.chmod(lexical.parent, 0o700)
            except OSError:
                pass
        self.key_path = lexical
        self.used_path = (used_path or lexical.with_name("approval-used.jsonl")).expanduser()
        if self.used_path.is_symlink():
            raise ApprovalError("approval replay store must not be a symlink")
        try:
            self._key_lock = FileLock(self.key_path.with_name(self.key_path.name + ".lock"))
            self._used_lock = FileLock(self.used_path.with_name(self.used_path.name + ".lock"))
            with self._key_lock:
                self._key = self._load_or_create_key_unlocked()
            with self._used_lock:
                self._consumed = self._load_consumed_unlocked()
        except LockError as exc:
            raise ApprovalError(str(exc)) from exc

    def close(self) -> None:
        for name in ("_key_lock", "_used_lock"):
            lock = getattr(self, name, None)
            if lock is not None:
                lock.close()
                setattr(self, name, None)

    def __del__(self) -> None:
        try:
            self.close()
        except OSError:
            pass

    def _load_or_create_key_unlocked(self) -> bytes:
        if self.key_path.is_symlink():
            raise ApprovalError("approval key must not be a symlink")
        if self.key_path.exists():
            info = self.key_path.stat()
            if not stat.S_ISREG(info.st_mode):
                raise ApprovalError("approval key must be a regular file")
            if os.name != "nt":
                if info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                    raise ApprovalError("approval key permissions must be 0600")
                if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
                    raise ApprovalError("approval key must be owned by current user")
            data = self.key_path.read_bytes()
            if len(data) != 32:
                raise ApprovalError("approval key has invalid length")
            return data

        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(self.key_path, flags, 0o600)
        try:
            data = secrets.token_bytes(32)
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        return data

    def _validate_used_store_unlocked(self) -> None:
        if self.used_path.is_symlink():
            raise ApprovalError("approval replay store must not be a symlink")
        if not self.used_path.exists():
            return
        info = self.used_path.stat()
        if not stat.S_ISREG(info.st_mode):
            raise ApprovalError("approval replay store must be a regular file")
        if os.name != "nt":
            if info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise ApprovalError("approval replay store permissions must be 0600")
            if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
                raise ApprovalError("approval replay store must be owned by current user")

    def _load_consumed_unlocked(self) -> set[str]:
        self._validate_used_store_unlocked()
        if not self.used_path.exists():
            return set()
        consumed: set[str] = set()
        try:
            for line in self.used_path.read_text(encoding="utf-8").splitlines():
                value = line.strip()
                if value:
                    consumed.add(value)
        except OSError as exc:
            raise ApprovalError(f"cannot read approval replay store: {exc}") from exc
        return consumed

    def _is_consumed(self, nonce: str) -> bool:
        try:
            with self._used_lock:
                current = self._load_consumed_unlocked()
                self._consumed = current
                return nonce in current
        except LockError as exc:
            raise ApprovalError(str(exc)) from exc

    def _consume_nonce(self, nonce: str) -> None:
        try:
            with self._used_lock:
                current = self._load_consumed_unlocked()
                if nonce in current:
                    self._consumed = current
                    raise ApprovalError("approval token was already used")

                flags = os.O_CREAT | os.O_WRONLY | os.O_APPEND
                if hasattr(os, "O_CLOEXEC"):
                    flags |= os.O_CLOEXEC
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                fd = os.open(self.used_path, flags, 0o600)
                try:
                    info = os.fstat(fd)
                    if not stat.S_ISREG(info.st_mode):
                        raise ApprovalError("approval replay store must be a regular file")
                    if os.name != "nt":
                        os.fchmod(fd, 0o600)
                        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
                            raise ApprovalError("approval replay store must be owned by current user")
                    os.write(fd, (nonce + "\n").encode("ascii"))
                    os.fsync(fd)
                finally:
                    os.close(fd)
                current.add(nonce)
                self._consumed = current
        except LockError as exc:
            raise ApprovalError(str(exc)) from exc

    def issue(
        self,
        *,
        workspace: Path,
        risk: RiskLevel,
        ttl_seconds: int = 300,
        action_hash: str | None = None,
    ) -> str:
        if not 1 <= ttl_seconds <= 3600:
            raise ApprovalError("approval ttl must be between 1 and 3600 seconds")
        payload: dict[str, Any] = {
            "v": 1,
            "workspace": workspace_id(workspace),
            "risk": risk.name,
            "exp": int(time.time()) + ttl_seconds,
            "nonce": secrets.token_hex(16),
        }
        if action_hash:
            payload["action"] = action_hash
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        sig = hmac.new(self._key, raw, hashlib.sha256).digest()
        return f"{_b64e(raw)}.{_b64e(sig)}"

    def validate(
        self,
        token: str | None,
        *,
        workspace: Path,
        minimum_risk: RiskLevel,
        action_hash: str | None = None,
        consume: bool = True,
    ) -> dict[str, Any]:
        if not token:
            raise ApprovalError(f"human approval token required for {minimum_risk.name} action")
        try:
            payload_part, sig_part = token.split(".", 1)
            raw = _b64d(payload_part)
            supplied = _b64d(sig_part)
            expected = hmac.new(self._key, raw, hashlib.sha256).digest()
            if not hmac.compare_digest(supplied, expected):
                raise ApprovalError("approval token signature is invalid")
            payload = json.loads(raw.decode("utf-8"))
        except ApprovalError:
            raise
        except Exception as exc:
            raise ApprovalError("approval token is malformed") from exc

        if payload.get("v") != 1:
            raise ApprovalError("approval token version is unsupported")
        if payload.get("workspace") != workspace_id(workspace):
            raise ApprovalError("approval token belongs to a different workspace")
        if int(payload.get("exp", 0)) < int(time.time()):
            raise ApprovalError("approval token has expired")
        try:
            token_risk = RiskLevel.parse(str(payload.get("risk", "")))
        except ValueError as exc:
            raise ApprovalError("approval token risk is invalid") from exc
        if token_risk < minimum_risk:
            raise ApprovalError("approval token does not cover this risk level")
        if action_hash is not None and payload.get("action") not in (None, action_hash):
            raise ApprovalError("approval token is bound to another action")

        nonce = str(payload.get("nonce", ""))
        if not nonce:
            raise ApprovalError("approval token nonce is invalid")
        if consume:
            self._consume_nonce(nonce)
        elif self._is_consumed(nonce):
            raise ApprovalError("approval token was already used")
        return payload
