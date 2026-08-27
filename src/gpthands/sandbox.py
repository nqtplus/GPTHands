from __future__ import annotations

import os
import platform
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .windows_classic import WindowsAppContainerSandbox
from .windows_sandbox import WindowsSandboxError


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
        elif system == "windows":
            if WindowsAppContainerSandbox.available():
                return SandboxPlan(backend="windows-appcontainer", argv=command)

        if self.require_os_sandbox:
            raise SandboxError(
                "OS sandbox is required but unavailable; install bubblewrap on Linux, use a supported macOS sandbox-exec environment, or use Windows with AppContainer support"
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

            if plan.backend == "windows-appcontainer":
                try:
                    result = WindowsAppContainerSandbox().run(
                        command=command,
                        workspace=workspace,
                        cwd=cwd,
                        allow_write=allow_write,
                        allow_network=allow_network,
                        isolated_home=isolated_home,
                        env=env,
                        timeout=timeout,
                        max_output_bytes=max_output_bytes,
                    )
                except WindowsSandboxError as exc:
                    raise SandboxError(str(exc)) from exc
                completed = subprocess.CompletedProcess(
                    args=command,
                    returncode=result.returncode,
                    stdout=result.output,
                    stderr=None,
                )
                return completed, result.backend

            proc_env = dict(env)
            if plan.backend == "bubblewrap":
                proc_env["HOME"] = "/tmp/gpthands-home"
                proc_env["TMPDIR"] = "/tmp"
            else:
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

        if plan.backend == "bubblewrap" and completed.returncode != 0:
            diagnostic = completed.stdout.decode("utf-8", errors="replace").strip()
            if diagnostic.startswith("bwrap:"):
                if not allow_network and (
                    "loopback" in diagnostic
                    or "RTM_NEWADDR" in diagnostic
                    or "network namespace" in diagnostic.lower()
                ):
                    raise SandboxError(
                        "Linux network namespace isolation is unavailable on this host; refusing to run the target process with network denied"
                    )
                raise SandboxError(f"bubblewrap sandbox setup failed: {diagnostic[:500]}")

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
        args += ["--dir", "/tmp/gpthands-home"]
        args += ["--setenv", "HOME", "/tmp/gpthands-home", "--setenv", "TMPDIR", "/tmp"]
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
            '(import "system.sb")',
            "(allow process-exec)",
            "(allow process-fork)",
            "(allow process-info* (target same-sandbox))",
            "(allow signal (target same-sandbox))",
            "(allow mach-priv-task-port (target same-sandbox))",
            "(allow sysctl-read)",
            "(allow mach-host*)",
            "(allow user-preference-read)",
            "(allow iokit-open)",
            "(allow ipc-posix-sem)",
            "(allow ipc-posix-shm-read*)",
            "(allow file-read-metadata)",
            "(allow file-ioctl)",
            "(allow mach-lookup",
            "  (global-name \"com.apple.logd\")",
            "  (global-name \"com.apple.system.logger\")",
            "  (global-name \"com.apple.system.notification_center\")",
            "  (global-name \"com.apple.system.opendirectoryd.libinfo\")",
            "  (global-name \"com.apple.SystemConfiguration.configd\")",
            "  (global-name \"com.apple.distributed_notifications@Uv3\"))",
            "(allow file-read* (subpath \"/usr\"))",
            "(allow file-read* (subpath \"/bin\"))",
            "(allow file-read* (subpath \"/sbin\"))",
            "(allow file-read* (subpath \"/System\"))",
            "(allow file-read* (subpath \"/Library\"))",
            "(allow file-read* (subpath \"/private/etc\"))",
            "(allow file-read* (subpath \"/private/var/db\"))",
            "(allow file-read* (literal \"/dev/random\"))",
            "(allow file-read* (literal \"/dev/urandom\"))",
            "(allow file-write* (literal \"/dev/null\"))",
            "(allow file-write* (literal \"/dev/zero\"))",
            f"(allow file-read* (subpath {q(workspace)}))",
            f"(allow file-read* file-write* (subpath {q(isolated_home)}))",
            "(allow file-read* file-write* (subpath \"/private/tmp\"))",
        ]
        if allow_write:
            lines.append(f"(allow file-write* (subpath {q(workspace)}))")
        if allow_network:
            lines += ["(allow network-outbound)", "(allow network-inbound)"]
        else:
            lines.append("(deny network*)")
        return "\n".join(lines)
