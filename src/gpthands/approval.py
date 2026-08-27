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
    def __init__(self, key_path: Path) -> None:
        self.key_path = key_path.expanduser()
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        self._key = self._load_or_create_key()
        self._consumed: set[str] = set()

    def _load_or_create_key(self) -> bytes:
        if self.key_path.exists():
            if self.key_path.is_symlink():
                raise ApprovalError("approval key must not be a symlink")
            info = self.key_path.stat()
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
        fd = os.open(self.key_path, flags, 0o600)
        try:
            data = secrets.token_bytes(32)
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        return data

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
        if not nonce or nonce in self._consumed:
            raise ApprovalError("approval token was already used")
        if consume:
            self._consumed.add(nonce)
        return payload
