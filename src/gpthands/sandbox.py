from __future__ import annotations

import os
import platform
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


class SandboxError(RuntimeError):
    pass


@dataclass(frozen=True)
class SandboxPlan:
    backend: str
    argv: list[str]
    profile_text: str | None = None


class SandboxRunner:
    def __init__(self, *, require_os_sandbox: bool = True) -> None:
        self.require_os_sandbox = require_os_sandbox

    def plan(
        self,
        *,
        command: list[str],
        workspace: Path,
        cwd: Path,
        allow_write: bool,
        allow_network: bool,
        isolated_home: Path,
    ) -> SandboxPlan:
        system = platform.system().lower()
        if system == "linux":
            bwrap = shutil.which("bwrap")
            if bwrap:
                return SandboxPlan(
                    backend="bubblewrap",
                    argv=self._linux_bwrap(
                        bwrap=bwrap,
                        command=command,
                        workspace=workspace,
                        cwd=cwd,
                        allow_write=allow_write,
                        allow_network=allow_network,
                        isolated_home=isolated_home,
                    ),
                )
        elif system == "darwin":
            sandbox_exec = shutil.which("sandbox-exec")
            if sandbox_exec:
                profile = self._macos_profile(
                    workspace=workspace,
                    allow_write=allow_write,
                    allow_network=allow_network,
                    isolated_home=isolated_home,
                )
                return SandboxPlan(
                    backend="sandbox-exec",
                    argv=[sandbox_exec, "-p", profile, *command],
                    profile_text=profile,
                )

        if self.require_os_sandbox:
            raise SandboxError(
                "OS sandbox is required but unavailable; install bubblewrap on Linux or use a supported macOS sandbox-exec environment"
            )
        return SandboxPlan(backend="policy-only", argv=command)

    def run(
        self,
        *,
        command: list[str],
        workspace: Path,
        cwd: Path,
        allow_write: bool,
        allow_network: bool,
        env: dict[str, str],
        timeout: int,
        max_output_bytes: int,
    ) -> tuple[subprocess.CompletedProcess[bytes], str]:
        with tempfile.TemporaryDirectory(prefix="gpthands-home-") as home_value:
            isolated_home = Path(home_value).resolve()
            plan = self.plan(
                command=command,
                workspace=workspace,
                cwd=cwd,
                allow_write=allow_write,
                allow_network=allow_network,
                isolated_home=isolated_home,
            )
            proc_env = dict(env)
            proc_env["HOME"] = str(isolated_home)
            proc_env["TMPDIR"] = str(isolated_home)
            try:
                completed = subprocess.run(
                    plan.argv,
                    cwd=cwd,
                    env=proc_env,
                    shell=False,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=timeout,
                    check=False,
                    start_new_session=True,
                )
            except subprocess.TimeoutExpired as exc:
                raise SandboxError(f"command exceeded {timeout}s timeout") from exc

        if len(completed.stdout) > max_output_bytes:
            completed.stdout = completed.stdout[:max_output_bytes] + b"\n[output truncated by GPTHands policy]"
        return completed, plan.backend

    @staticmethod
    def _linux_bwrap(
        *,
        bwrap: str,
        command: list[str],
        workspace: Path,
        cwd: Path,
        allow_write: bool,
        allow_network: bool,
        isolated_home: Path,
    ) -> list[str]:
        args = [
            bwrap,
            "--die-with-parent",
            "--new-session",
            "--unshare-all",
        ]
        if allow_network:
            args.append("--share-net")

        for system_path in ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"):
            if Path(system_path).exists():
                args += ["--ro-bind", system_path, system_path]
        args += ["--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp"]
        args += ["--dir", "/home", "--bind", str(isolated_home), str(isolated_home)]
        args += ["--setenv", "HOME", str(isolated_home), "--setenv", "TMPDIR", "/tmp"]
        args += ["--bind" if allow_write else "--ro-bind", str(workspace), str(workspace)]
        args += ["--chdir", str(cwd), "--"]
        args.extend(command)
        return args

    @staticmethod
    def _macos_profile(
        *,
        workspace: Path,
        allow_write: bool,
        allow_network: bool,
        isolated_home: Path,
    ) -> str:
        def q(path: Path | str) -> str:
            value = str(path).replace('\\', '\\\\').replace('"', '\\"')
            return f'"{value}"'

        lines = [
            "(version 1)",
            "(deny default)",
            "(allow process-exec)",
            "(allow process-fork)",
            "(allow sysctl-read)",
            "(allow file-read-metadata)",
            "(allow file-read* (subpath \"/usr\"))",
            "(allow file-read* (subpath \"/bin\"))",
            "(allow file-read* (subpath \"/sbin\"))",
            "(allow file-read* (subpath \"/System\"))",
            "(allow file-read* (subpath \"/Library\"))",
            f"(allow file-read* (subpath {q(workspace)}))",
            f"(allow file-read* file-write* (subpath {q(isolated_home)}))",
            "(allow file-write* (subpath \"/private/tmp\"))",
        ]
        if allow_write:
            lines.append(f"(allow file-write* (subpath {q(workspace)}))")
        if allow_network:
            lines += ["(allow network-outbound)", "(allow network-inbound)"]
        return "\n".join(lines)
