from __future__ import annotations

import re
from enum import IntEnum
from pathlib import Path
from typing import Iterable


class RiskLevel(IntEnum):
    READ = 10
    WRITE = 20
    EXEC = 30
    NETWORK = 40
    DESTRUCTIVE = 50

    @classmethod
    def parse(cls, value: str) -> "RiskLevel":
        try:
            return cls[value.strip().upper()]
        except (KeyError, AttributeError) as exc:
            raise ValueError(f"unknown risk level: {value}") from exc


_DANGEROUS_ARG_PATTERNS = (
    re.compile(r"(^|\s)--privileged($|\s)"),
    re.compile(r"(^|\s)--force(?:-with-lease)?($|\s)"),
    re.compile(r"(^|\s)-f($|\s)"),
    re.compile(r"(^|\s)reset\s+--hard($|\s)"),
    re.compile(r"(^|\s)clean\s+-[^\s]*f"),
    re.compile(r"(^|\s)rm\s+-[^\s]*r"),
)

_ARBITRARY_CODE_PROGRAMS = {
    "bash",
    "sh",
    "zsh",
    "fish",
    "python",
    "python3",
    "node",
    "ruby",
    "perl",
    "php",
    "pwsh",
    "powershell",
    "cmd",
    "wscript",
    "cscript",
    "mshta",
}

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
    "gh",
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

_EXECUTABLE_SUFFIXES = (".exe", ".cmd", ".bat", ".com")


def normalized_program(value: str) -> str:
    name = Path(value).name.lower()
    for suffix in _EXECUTABLE_SUFFIXES:
        if name.endswith(suffix) and len(name) > len(suffix):
            return name[: -len(suffix)]
    return name


def command_requires_network(argv: Iterable[str]) -> bool:
    args = list(argv)
    if not args:
        return False
    program = normalized_program(args[0])
    if program in _NETWORK_PROGRAMS:
        return True
    network_subcommands = _NETWORK_SUBCOMMANDS.get(program, set())
    return any(arg.lower() in network_subcommands for arg in args[1:])


def classify_command(argv: Iterable[str]) -> RiskLevel:
    args = list(argv)
    if not args:
        return RiskLevel.EXEC
    program = normalized_program(args[0])
    joined = " ".join(args).lower()
    if program in _ARBITRARY_CODE_PROGRAMS:
        return RiskLevel.DESTRUCTIVE
    if any(pattern.search(joined) for pattern in _DANGEROUS_ARG_PATTERNS):
        return RiskLevel.DESTRUCTIVE
    if command_requires_network(args):
        return RiskLevel.NETWORK
    return RiskLevel.EXEC
