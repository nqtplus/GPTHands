from __future__ import annotations

import os
import signal
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path


class ProcessControlError(RuntimeError):
    pass


@dataclass(frozen=True)
class BoundedProcessResult:
    returncode: int
    stdout: bytes


def _kill_process_tree(process: subprocess.Popen[bytes]) -> None:
    if os.name != "nt":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    else:  # defensive fallback only; secure Windows execution uses Job Objects
        try:
            process.kill()
        except OSError:
            pass


def run_bounded_process(
    argv: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: int,
    max_output_bytes: int,
) -> BoundedProcessResult:
    """Run argv with bounded output capture and full-tree timeout cleanup.

    POSIX stdout is drained incrementally so an allowed command cannot force the
    host to buffer arbitrarily large output in memory before the policy limit is
    applied. Only the first ``max_output_bytes`` bytes are retained; excess data
    is discarded while the pipe continues to be drained so the child cannot
    block on a full pipe.

    On POSIX, a new session is created and descendants are killed on timeout and
    after the root command exits, preventing background children from outliving
    the action. Secure Windows execution uses the dedicated AppContainer + Job
    Object backend and does not call this helper for generic execution.
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
    if process.stdout is None:  # pragma: no cover - guaranteed by stdout=PIPE
        _kill_process_tree(process)
        raise ProcessControlError("process stdout pipe was not created")

    captured = bytearray()
    truncated = [False]
    reader_errors: list[BaseException] = []

    def drain_stdout() -> None:
        try:
            while True:
                chunk = process.stdout.read(64 * 1024)
                if not chunk:
                    break
                remaining = max_output_bytes - len(captured)
                if remaining > 0:
                    captured.extend(chunk[:remaining])
                if len(chunk) > max(remaining, 0):
                    truncated[0] = True
        except (OSError, ValueError) as exc:
            reader_errors.append(exc)

    reader = threading.Thread(target=drain_stdout, name="gpthands-stdout-drain", daemon=True)
    reader.start()

    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        _kill_process_tree(process)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _kill_process_tree(process)
        reader.join(timeout=5)
        if reader.is_alive():
            try:
                process.stdout.close()
            except OSError:
                pass
            reader.join(timeout=1)
        raise ProcessControlError(
            f"command exceeded {timeout}s timeout; process tree terminated"
        ) from exc

    # Synchronous run_command actions must not leave daemonized descendants.
    # If a descendant inherited stdout, killing the original process group also
    # closes that inherited pipe and lets the bounded drain thread finish.
    if os.name != "nt":
        _kill_process_tree(process)

    reader.join(timeout=5)
    if reader.is_alive():
        try:
            process.stdout.close()
        except OSError:
            pass
        reader.join(timeout=1)
    if reader.is_alive():
        raise ProcessControlError("stdout drain did not terminate after process-tree cleanup")
    if reader_errors:
        raise ProcessControlError(f"stdout capture failed: {reader_errors[0]}")

    output = bytes(captured)
    if truncated[0]:
        output += b"\n[output truncated by GPTHands policy]"
    return BoundedProcessResult(returncode=int(process.returncode), stdout=output)
