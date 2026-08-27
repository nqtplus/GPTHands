from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .credentials import CredentialStore, CredentialStoreError


class TunnelError(RuntimeError):
    pass


_TUNNEL_ID = re.compile(r"^tunnel_[0-9a-f]{32}$")


@dataclass(frozen=True)
class TunnelPlan:
    executable: str
    profile: str
    init_argv: list[str]
    doctor_argv: list[str]
    run_argv: list[str]


def _mcp_command(workspace: Path) -> str:
    argv = ["gpthands", "serve", "--workspace", str(workspace.resolve(strict=True))]
    if os.name == "nt":
        return subprocess.list2cmdline(argv)
    return shlex.join(argv)


def find_tunnel_client(override: str | None = None) -> str:
    candidate = override or os.environ.get("GPTHANDS_TUNNEL_CLIENT") or shutil.which("tunnel-client")
    if not candidate:
        raise TunnelError("official tunnel-client binary was not found; install openai/tunnel-client first")
    path = Path(candidate).expanduser()
    if path.is_absolute() and not path.exists():
        raise TunnelError("configured tunnel-client binary does not exist")
    return str(path if path.is_absolute() else candidate)


def build_tunnel_plan(*, workspace: Path, tunnel_id: str, profile: str = "gpthands", binary: str | None = None) -> TunnelPlan:
    if not _TUNNEL_ID.fullmatch(tunnel_id.strip()):
        raise TunnelError("tunnel id must match tunnel_<32 lowercase hex characters>")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", profile):
        raise TunnelError("profile name is invalid")
    executable = find_tunnel_client(binary)
    command = _mcp_command(workspace)
    init_argv = [
        executable,
        "init",
        "--profile",
        profile,
        "--tunnel-id",
        tunnel_id,
        "--control-plane-api-key-ref",
        "env:CONTROL_PLANE_API_KEY",
        "--mcp-command",
        command,
        "--health-listen-addr",
        "127.0.0.1:0",
    ]
    return TunnelPlan(
        executable=executable,
        profile=profile,
        init_argv=init_argv,
        doctor_argv=[executable, "doctor", "--profile", profile],
        run_argv=[executable, "run", "--profile", profile],
    )


def _runtime_env(credential_name: str | None) -> dict[str, str]:
    env = dict(os.environ)
    if credential_name:
        try:
            env["CONTROL_PLANE_API_KEY"] = CredentialStore().get(credential_name)
        except CredentialStoreError as exc:
            raise TunnelError(str(exc)) from exc
    return env


def execute_tunnel_step(argv: list[str], *, credential_name: str | None = None, timeout: int | None = 60) -> subprocess.CompletedProcess[str]:
    if not argv:
        raise TunnelError("empty tunnel command")
    effective_timeout = None if len(argv) > 1 and argv[1] == "run" else timeout
    try:
        completed = subprocess.run(
            argv,
            env=_runtime_env(credential_name),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            shell=False,
            timeout=effective_timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise TunnelError(f"tunnel-client execution failed: {exc}") from exc
    return completed
