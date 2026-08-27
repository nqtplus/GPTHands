from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


class PolicyError(RuntimeError):
    """Raised when a requested action violates local GPTHands policy."""


_SECRET_NAME_PATTERNS = (
    re.compile(r"^\.env(?:\..+)?$", re.IGNORECASE),
    re.compile(r".*\.(?:pem|key|p12|pfx)$", re.IGNORECASE),
    re.compile(r"^(?:id_rsa|id_ed25519|credentials|credentials\.json|service-account\.json)$", re.IGNORECASE),
    re.compile(r"^\.git-credentials$", re.IGNORECASE),
)

_SECRET_DIR_NAMES = {".ssh", ".aws", ".gnupg"}
_PROTECTED_NAMES = {".gpthands.json"}

_DANGEROUS_ARG_PATTERNS = (
    re.compile(r"(^|\s)--privileged($|\s)"),
    re.compile(r"(^|\s)--force($|\s)"),
    re.compile(r"(^|\s)-f($|\s)"),
    re.compile(r"(^|\s)reset\s+--hard($|\s)"),
    re.compile(r"(^|\s)clean\s+-[^\s]*f"),
)

_NETWORK_PROGRAMS = {
    "curl",
    "wget",
    "nc",
    "netcat",
    "ssh",
    "scp",
    "sftp",
    "ftp",
    "telnet",
}

_NETWORK_SUBCOMMANDS = {
    "git": {"clone", "fetch", "pull", "push", "ls-remote"},
    "npm": {"install", "i", "update", "audit", "publish", "login", "whoami"},
    "pnpm": {"install", "add", "update", "publish", "audit"},
    "yarn": {"install", "add", "upgrade", "publish", "npm"},
    "pip": {"install", "download", "index"},
    "pip3": {"install", "download", "index"},
    "cargo": {"fetch", "install", "publish", "search", "login"},
    "go": {"get", "install"},
}


@dataclass(frozen=True)
class Policy:
    workspace: Path
    allow_write: bool = False
    allow_process: bool = False
    allow_network_commands: bool = False
    allowed_commands: tuple[str, ...] = field(default_factory=tuple)
    max_read_bytes: int = 1_000_000
    max_write_bytes: int = 1_000_000
    max_command_seconds: int = 30
    max_output_bytes: int = 200_000

    @staticmethod
    def load(workspace: Path) -> "Policy":
        root = workspace.expanduser().resolve(strict=True)
        if not root.is_dir():
            raise PolicyError(f"workspace is not a directory: {root}")

        config_path = root / ".gpthands.json"
        raw: dict[str, object] = {}
        if config_path.exists():
            if config_path.is_symlink():
                raise PolicyError(".gpthands.json must not be a symlink")
            config_stat = config_path.stat()
            if os.name != "nt" and config_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise PolicyError(".gpthands.json must not be group/world writable")
            if hasattr(os, "geteuid") and config_stat.st_uid != os.geteuid():
                raise PolicyError(".gpthands.json must be owned by the current user")
            try:
                raw = json.loads(config_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise PolicyError(f"invalid .gpthands.json: {exc}") from exc

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

        return Policy(
            workspace=root,
            allow_write=bool_value("allow_write", False),
            allow_process=bool_value("allow_process", False),
            allow_network_commands=bool_value("allow_network_commands", False),
            allowed_commands=tuple(allowed),
            max_read_bytes=int_value("max_read_bytes", 1_000_000, 1, 20_000_000),
            max_write_bytes=int_value("max_write_bytes", 1_000_000, 1, 20_000_000),
            max_command_seconds=int_value("max_command_seconds", 30, 1, 600),
            max_output_bytes=int_value("max_output_bytes", 200_000, 1_000, 5_000_000),
        )

    def resolve_path(self, target: str, *, must_exist: bool = False) -> Path:
        if not isinstance(target, str) or not target.strip():
            raise PolicyError("target path must be a non-empty string")
        requested = Path(target)
        if requested.is_absolute():
            raise PolicyError("absolute paths are not allowed")

        candidate = (self.workspace / requested).resolve(strict=must_exist)
        try:
            common = Path(os.path.commonpath((str(self.workspace), str(candidate))))
        except ValueError as exc:
            raise PolicyError("path is outside workspace") from exc
        if common != self.workspace:
            raise PolicyError("path escapes workspace")

        self._check_protected_path(candidate)
        self._check_secret_path(candidate)
        return candidate

    def require_write(self) -> None:
        if not self.allow_write:
            raise PolicyError("write capability is disabled by local policy")

    def validate_command(self, argv: Iterable[str]) -> list[str]:
        if not self.allow_process:
            raise PolicyError("process capability is disabled by local policy")

        args = list(argv)
        if not args or not all(isinstance(x, str) and x for x in args):
            raise PolicyError("command must be a non-empty string array")

        program = Path(args[0]).name
        if program not in self.allowed_commands:
            raise PolicyError(f"command is not allowlisted: {program}")

        if not self.allow_network_commands:
            if program in _NETWORK_PROGRAMS:
                raise PolicyError(f"network-capable command is disabled: {program}")
            if len(args) > 1 and args[1].lower() in _NETWORK_SUBCOMMANDS.get(program, set()):
                raise PolicyError(f"network-capable subcommand is disabled: {program} {args[1]}")

        joined = " ".join(args).lower()
        for pattern in _DANGEROUS_ARG_PATTERNS:
            if pattern.search(joined):
                raise PolicyError("dangerous command arguments require a future approval flow")

        return args

    @staticmethod
    def _check_protected_path(path: Path) -> None:
        if path.name.lower() in _PROTECTED_NAMES:
            raise PolicyError("policy authority file is protected from MCP tools")

    @staticmethod
    def _check_secret_path(path: Path) -> None:
        lowered_parts = {part.lower() for part in path.parts}
        if lowered_parts.intersection(_SECRET_DIR_NAMES):
            raise PolicyError("access to secret directory is denied")

        name = path.name
        if any(pattern.match(name) for pattern in _SECRET_NAME_PATTERNS):
            raise PolicyError("access to secret-like file is denied")

        # Block common credential files inside .config without denying all .config usage.
        lower = str(path).lower().replace("\\", "/")
        if "/.config/gcloud/" in lower or "/.config/gh/hosts.yml" in lower:
            raise PolicyError("access to credential path is denied")
