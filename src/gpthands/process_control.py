from __future__ import annotations

import os
import signal
import subprocess
from dataclasses import dataclass
from pathlib import Path


class ProcessControlError(RuntimeError):
    pass


@dataclass(frozen=True)
class BoundedProcessResult:
    returncode: int
    stdout: bytes


def run_bounded_process(
    argv: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: int,
    max_output_bytes: int,
) -> BoundedProcessResult:
    """Run argv in a new process group/session and kill the full tree on timeout.

    On POSIX, a new session is created and timeout cleanup targets the process
    group rather than only the immediate child. Windows process execution uses
    the dedicated AppContainer + Job Object backend and does not call this
    helper for secure generic execution.
    """
    if not argv:
        raise ProcessControlError("empty process argv")
    if timeout < 1:
        raise ProcessControlError("timeout must be positive")
    if max_output_bytes < 1:
        raise ProcessControlError("max_output_bytes must be positive")

    kwargs: dict[str, object] = {
        "cwd": cwd,
        "env": env,
        "shell": False,
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
    }
    if os.name != "nt":
        kwargs["start_new_session"] = True
    else:  # defensive fallback only; secure Windows execution uses Job Objects
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)

    process = subprocess.Popen(argv, **kwargs)  # type: ignore[arg-type]
    try:
        stdout, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        if os.name != "nt":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            process.kill()
        try:
            stdout, _ = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, _ = process.communicate()
        raise ProcessControlError(f"command exceeded {timeout}s timeout; process tree terminated") from exc

    if len(stdout) > max_output_bytes:
        stdout = stdout[:max_output_bytes] + b"\n[output truncated by GPTHands policy]"
    return BoundedProcessResult(returncode=int(process.returncode), stdout=stdout)
