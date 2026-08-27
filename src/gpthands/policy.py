from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .risk import RiskLevel, classify_command, command_requires_network


class PolicyError(RuntimeError):
    """Raised when a requested action violates local GPTHands policy."""


POLICY_SCHEMA_VERSION = 3
_SECRET_SUFFIXES = {".pem", ".key", ".p12", ".pfx"}
_SECRET_NAMES = {
    ".env",
    "id_rsa",
    "id_ed25519",
    "credentials",
    "credentials.json",
    "service-account.json",
    ".git-credentials",
}
_SECRET_DIR_NAMES = {".ssh", ".aws", ".gnupg"}
_PROTECTED_NAMES = {".gpthands.json", ".gpthands-policy.json"}
_MAX_LEASE_SECONDS = 86_400
_POLICY_KEYS = {
    "schema_version",
    "allow_write",
    "allow_process",
    "allow_network_commands",
    "write_lease_until",
    "process_lease_until",
    "network_lease_until",
    "allowed_commands",
    "approval_required_from",
    "require_os_sandbox",
    "max_read_bytes",
    "max_write_bytes",
    "max_command_seconds",
    "max_output_bytes",
    "max_requests_per_minute",
    "max_concurrent_actions",
    "max_queue_seconds",
}


def _workspace_id(workspace: Path) -> str:
    return hashlib.sha256(str(workspace.resolve(strict=True)).encode("utf-8")).hexdigest()[:24]


def default_policy_path(workspace: Path) -> Path:
    root = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return root / "gpthands" / "policies" / f"{_workspace_id(workspace)}.json"


def _inside(root: Path, candidate: Path) -> bool:
    try:
        return os.path.commonpath((str(root), str(candidate))) == str(root)
    except ValueError:
        return False


def _parse_expiry(value: object, *, name: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, str):
        text = value.strip()
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError as exc:
            raise PolicyError(f"{name} must be an ISO-8601 timestamp or unix time") from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    raise PolicyError(f"{name} must be an ISO-8601 timestamp or unix time")


def _live(expiry: float | None) -> bool:
    return expiry is not None and expiry > time.time()


def migrate_policy_data(raw: dict[str, object]) -> dict[str, object]:
    """Normalize supported historical policy formats to the current schema."""
    if not isinstance(raw, dict):
        raise PolicyError("policy root must be an object")
    migrated = dict(raw)
    version_raw = migrated.get("schema_version", 2)
    if not isinstance(version_raw, int) or isinstance(version_raw, bool):
        raise PolicyError("schema_version must be an integer")
    if version_raw < 1 or version_raw > POLICY_SCHEMA_VERSION:
        raise PolicyError(f"unsupported policy schema_version: {version_raw}")

    # v1 used the shorter allow_network spelling in early development builds.
    if version_raw == 1 and "allow_network" in migrated:
        if "allow_network_commands" in migrated:
            raise PolicyError("policy contains both allow_network and allow_network_commands")
        migrated["allow_network_commands"] = migrated.pop("allow_network")

    unknown = sorted(set(migrated) - _POLICY_KEYS)
    if unknown:
        raise PolicyError(f"unknown policy field(s): {', '.join(unknown)}")
    migrated["schema_version"] = POLICY_SCHEMA_VERSION
    return migrated


@dataclass(frozen=True)
class Policy:
    workspace: Path
    policy_path: Path
    schema_version: int = POLICY_SCHEMA_VERSION
    write_enabled: bool = False
    process_enabled: bool = False
    network_enabled: bool = False
    require_os_sandbox: bool = True
    approval_required_from: RiskLevel = RiskLevel.EXEC
    allowed_commands: tuple[str, ...] = field(default_factory=tuple)
    max_read_bytes: int = 1_000_000
    max_write_bytes: int = 1_000_000
    max_command_seconds: int = 30
    max_output_bytes: int = 200_000
    max_requests_per_minute: int = 120
    max_concurrent_actions: int = 4
    max_queue_seconds: int = 2
    write_lease_until: float | None = None
    process_lease_until: float | None = None
    network_lease_until: float | None = None

    @property
    def allow_write(self) -> bool:
        return self.write_enabled and _live(self.write_lease_until)

    @property
    def allow_process(self) -> bool:
        return self.process_enabled and _live(self.process_lease_until)

    @property
    def allow_network_commands(self) -> bool:
        return self.network_enabled and self.allow_process and _live(self.network_lease_until)

    @staticmethod
    def load(workspace: Path, policy_path: Path | None = None) -> "Policy":
        root = workspace.expanduser().resolve(strict=True)
        if not root.is_dir():
            raise PolicyError(f"workspace is not a directory: {root}")

        lexical = Path(os.path.abspath((policy_path or default_policy_path(root)).expanduser()))
        if lexical.is_symlink():
            raise PolicyError("policy file must not be a symlink")
        resolved_parent = lexical.parent.resolve(strict=False)
        path = resolved_parent / lexical.name
        if _inside(root, path):
            raise PolicyError("policy authority must live outside the workspace")

        raw: dict[str, object] = {}
        if path.exists():
            info = path.stat()
            if not stat.S_ISREG(info.st_mode):
                raise PolicyError("policy file must be a regular file")
            if os.name != "nt":
                if info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                    raise PolicyError("policy file permissions must be 0600")
                if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
                    raise PolicyError("policy file must be owned by current user")
                parent_info = path.parent.stat()
                if parent_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                    raise PolicyError("policy directory must not be group/world writable")
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise PolicyError(f"invalid policy file: {exc}") from exc
            if not isinstance(loaded, dict):
                raise PolicyError("policy root must be an object")
            raw = migrate_policy_data(loaded)
        else:
            raw = {"schema_version": POLICY_SCHEMA_VERSION}

        allowed = raw.get("allowed_commands", [])
        if not isinstance(allowed, list) or not all(isinstance(x, str) and x for x in allowed):
            raise PolicyError("allowed_commands must be a list of non-empty strings")

        def bool_value(name: str, default: bool) -> bool:
            value = raw.get(name, default)
            if not isinstance(value, bool):
                raise PolicyError(f"{name} must be boolean")
            return value

        def int_value(name: str, default: int, minimum: int, maximum: int) -> int:
            value = raw.get(name, default)
            if not isinstance(value, int) or isinstance(value, bool):
                raise PolicyError(f"{name} must be an integer")
            if not minimum <= value <= maximum:
                raise PolicyError(f"{name} must be between {minimum} and {maximum}")
            return value

        now = time.time()
        write_exp = _parse_expiry(raw.get("write_lease_until"), name="write_lease_until")
        process_exp = _parse_expiry(raw.get("process_lease_until"), name="process_lease_until")
        network_exp = _parse_expiry(raw.get("network_lease_until"), name="network_lease_until")
        for name, expiry in (
            ("write_lease_until", write_exp),
            ("process_lease_until", process_exp),
            ("network_lease_until", network_exp),
        ):
            if expiry is not None and expiry > now + _MAX_LEASE_SECONDS + 1:
                raise PolicyError(f"{name} cannot grant more than 24 hours of authority")

        approval_raw = raw.get("approval_required_from", "EXEC")
        if not isinstance(approval_raw, str):
            raise PolicyError("approval_required_from must be a risk level string")
        try:
            approval_level = RiskLevel.parse(approval_raw)
        except ValueError as exc:
            raise PolicyError(str(exc)) from exc

        return Policy(
            workspace=root,
            policy_path=path,
            schema_version=POLICY_SCHEMA_VERSION,
            write_enabled=bool_value("allow_write", False),
            process_enabled=bool_value("allow_process", False),
            network_enabled=bool_value("allow_network_commands", False),
            require_os_sandbox=bool_value("require_os_sandbox", True),
            approval_required_from=approval_level,
            allowed_commands=tuple(allowed),
            max_read_bytes=int_value("max_read_bytes", 1_000_000, 1, 20_000_000),
            max_write_bytes=int_value("max_write_bytes", 1_000_000, 1, 20_000_000),
            max_command_seconds=int_value("max_command_seconds", 30, 1, 600),
            max_output_bytes=int_value("max_output_bytes", 200_000, 1_000, 5_000_000),
            max_requests_per_minute=int_value("max_requests_per_minute", 120, 1, 6000),
            max_concurrent_actions=int_value("max_concurrent_actions", 4, 1, 64),
            max_queue_seconds=int_value("max_queue_seconds", 2, 0, 30),
            write_lease_until=write_exp,
            process_lease_until=process_exp,
            network_lease_until=network_exp,
        )

    def resolve_path(self, target: str, *, must_exist: bool = False) -> Path:
        if not isinstance(target, str) or not target.strip():
            raise PolicyError("target path must be a non-empty string")
        requested = Path(target)
        if requested.is_absolute():
            raise PolicyError("absolute paths are not allowed")

        candidate = (self.workspace / requested).resolve(strict=must_exist)
        if not _inside(self.workspace, candidate):
            raise PolicyError("path escapes workspace")

        self._check_protected_path(candidate)
        self._check_secret_path(candidate)
        return candidate

    def require_write(self) -> None:
        if not self.allow_write:
            raise PolicyError("write capability is disabled or its lease expired")

    def approval_required(self, risk: RiskLevel) -> bool:
        return risk >= self.approval_required_from

    def validate_command(self, argv: Iterable[str]) -> tuple[list[str], RiskLevel]:
        if not self.allow_process:
            raise PolicyError("process capability is disabled or its lease expired")

        args = list(argv)
        if not args or not all(isinstance(x, str) and x for x in args):
            raise PolicyError("command must be a non-empty string array")

        raw_program = args[0]
        if Path(raw_program).name != raw_program:
            raise PolicyError("command executable must be a bare allowlisted name; paths are not allowed")
        if raw_program not in self.allowed_commands:
            raise PolicyError(f"command is not allowlisted: {raw_program}")

        risk = classify_command(args)
        if command_requires_network(args) and not self.allow_network_commands:
            raise PolicyError("network capability is disabled or its lease expired")
        return args, risk

    @staticmethod
    def _check_protected_path(path: Path) -> None:
        if path.name.lower() in _PROTECTED_NAMES:
            raise PolicyError("policy authority file is protected from MCP tools")

    @staticmethod
    def _check_secret_path(path: Path) -> None:
        lowered_parts = {part.lower() for part in path.parts}
        if lowered_parts.intersection(_SECRET_DIR_NAMES):
            raise PolicyError("access to secret directory is denied")

        name = path.name.lower()
        if name in _SECRET_NAMES or name.startswith(".env.") or path.suffix.lower() in _SECRET_SUFFIXES:
            raise PolicyError("access to secret-like file is denied")

        lower = str(path).lower().replace("\\", "/")
        if "/.config/gcloud/" in lower or "/.config/gh/hosts.yml" in lower:
            raise PolicyError("access to credential path is denied")
