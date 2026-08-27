from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path

from .audit import redact_text
from .credentials import CredentialStore, CredentialStoreError


class TunnelError(RuntimeError):
    pass


_TUNNEL_ID = re.compile(r"^tunnel_[0-9a-f]{32}$")
_MAX_TUNNEL_OUTPUT_BYTES = 1_000_000
_TRUNCATED = "\n[output truncated by GPTHands tunnel policy]"


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


def _runtime_env(credential_name: str | None) -> tuple[dict[str, str], str | None]:
    env = dict(os.environ)
    secret: str | None = None
    if credential_name:
        try:
            secret = CredentialStore().get(credential_name)
            env["CONTROL_PLANE_API_KEY"] = secret
        except CredentialStoreError as exc:
            raise TunnelError(str(exc)) from exc
    return env, secret


def _redact_tunnel_output(text: str, secret: str | None) -> str:
    if secret:
        text = text.replace(secret, "[REDACTED]")
    return redact_text(text)


def execute_tunnel_step(
    argv: list[str],
    *,
    credential_name: str | None = None,
    timeout: int | None = 60,
) -> subprocess.CompletedProcess[str]:
    if not argv:
        raise TunnelError("empty tunnel command")
    effective_timeout = None if len(argv) > 1 and argv[1] == "run" else timeout
    env, secret = _runtime_env(credential_name)

    try:
        process = subprocess.Popen(
            argv,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=False,
            shell=False,
        )
    except OSError as exc:
        raise TunnelError(f"tunnel-client execution failed: {exc}") from exc

    if process.stdout is None:  # pragma: no cover - guaranteed by PIPE
        process.kill()
        raise TunnelError("tunnel-client stdout pipe was not created")

    retained = bytearray()
    truncated = [False]
    read_error: list[BaseException] = []

    def drain() -> None:
        try:
            while True:
                chunk = process.stdout.read(64 * 1024)
                if not chunk:
                    break
                remaining = _MAX_TUNNEL_OUTPUT_BYTES - len(retained)
                if remaining > 0:
                    retained.extend(chunk[:remaining])
                if len(chunk) > max(remaining, 0):
                    truncated[0] = True
        except (OSError, ValueError) as exc:
            read_error.append(exc)

    reader = threading.Thread(target=drain, name="gpthands-tunnel-output", daemon=True)
    reader.start()
    try:
        process.wait(timeout=effective_timeout)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
        reader.join(timeout=5)
        raise TunnelError("tunnel-client execution timed out") from exc

    reader.join(timeout=5)
    if reader.is_alive():
        try:
            process.stdout.close()
        except OSError:
            pass
        reader.join(timeout=1)
    if reader.is_alive():
        raise TunnelError("tunnel-client output drain did not terminate")
    if read_error:
        raise TunnelError(f"tunnel-client output capture failed: {type(read_error[0]).__name__}")

    output = retained.decode("utf-8", errors="replace")
    if truncated[0]:
        output += _TRUNCATED
    output = _redact_tunnel_output(output, secret)
    return subprocess.CompletedProcess(argv, int(process.returncode), stdout=output, stderr=None)
