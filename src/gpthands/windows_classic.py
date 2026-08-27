from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
from pathlib import Path

from . import windows_sandbox as ws
from .windows_job import WindowsJobError, WindowsJobObject
from .windows_paths import WindowsPathError, assert_no_reparse_tree

_CREATE_SUSPENDED = 0x00000004


class WindowsAppContainerSandbox(ws.WindowsAppContainerSandbox):
    """Stable Windows AppContainer backend with Job Object tree containment.

    v1 deliberately uses the classic AppContainer launch path because it lets
    GPTHands create the process suspended, attach the process to an owner-side
    Job Object, verify membership, and only then resume execution. This removes
    the attach-after-start race and gives deterministic descendant cleanup.
    """

    def run(
        self,
        *,
        command: list[str],
        workspace: Path,
        cwd: Path,
        allow_write: bool,
        allow_network: bool,
        isolated_home: Path,
        env: dict[str, str],
        timeout: int,
        max_output_bytes: int,
    ) -> ws.WindowsSandboxResult:
        if not self._classic_available:
            raise ws.WindowsSandboxError("stable classic Windows AppContainer backend is unavailable")
        try:
            assert_no_reparse_tree(workspace)
        except WindowsPathError as exc:
            raise ws.WindowsSandboxError(str(exc)) from exc
        return self._run_classic(
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

    @staticmethod
    def _classic_environment(env: dict[str, str], scratch: Path):
        values = ws._safe_windows_env(env, scratch)
        local_app_data = os.environ.get("LOCALAPPDATA")
        if not local_app_data:
            raise ws.WindowsSandboxError("LOCALAPPDATA is required to launch a classic Windows AppContainer")
        values["LOCALAPPDATA"] = local_app_data
        system_drive = os.environ.get("SystemDrive")
        if system_drive:
            values.setdefault("SystemDrive", system_drive)
        return ws._environment_block(values)

    @staticmethod
    def _icacls(path: Path, *args: str) -> None:
        completed = subprocess.run(
            ["icacls.exe", str(path), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
            check=False,
        )
        if completed.returncode != 0:
            raise ws.WindowsSandboxError(
                f"icacls failed for {path}: {completed.stdout.decode(errors='replace')[:500]}"
            )

    @classmethod
    def _grant_appcontainer_paths(
        cls,
        *,
        root: Path,
        staged: Path,
        scratch: Path,
        sid_text: str,
        allow_write: bool,
    ) -> None:
        cls._icacls(root, "/grant", f"*{sid_text}:(RX)", "/Q")
        cls._icacls(root, "/setintegritylevel", "L", "/Q")

        stage_rights = "M" if allow_write else "RX"
        cls._icacls(staged, "/grant", f"*{sid_text}:(OI)(CI){stage_rights}", "/T", "/C", "/Q")
        cls._icacls(staged, "/setintegritylevel", "(OI)(CI)L", "/T", "/C", "/Q")

        cls._icacls(scratch, "/grant", f"*{sid_text}:(OI)(CI)M", "/T", "/C", "/Q")
        cls._icacls(scratch, "/setintegritylevel", "(OI)(CI)L", "/T", "/C", "/Q")

    def _wait_in_job(self, info: ws.PROCESS_INFORMATION, timeout: int) -> int:
        self._kernel32.ResumeThread.restype = ws.wintypes.DWORD
        self._kernel32.ResumeThread.argtypes = [ws.wintypes.HANDLE]
        job: WindowsJobObject | None = None
        try:
            job = WindowsJobObject.create(max_processes=32)
            job.assign(info.hProcess)
            resume = self._kernel32.ResumeThread(info.hThread)
            if resume == 0xFFFFFFFF:
                raise ws.WindowsSandboxError(f"ResumeThread failed: {ctypes.get_last_error()}")

            wait = self._kernel32.WaitForSingleObject(info.hProcess, max(1, timeout) * 1000)
            if wait == ws._WAIT_TIMEOUT:
                job.terminate(124)
                self._kernel32.WaitForSingleObject(info.hProcess, 5000)
                raise ws.WindowsSandboxError(f"command exceeded {timeout}s timeout; Windows Job Object terminated the process tree")
            if wait != ws._WAIT_OBJECT_0:
                job.terminate(125)
                raise ws.WindowsSandboxError(f"WaitForSingleObject failed: {ctypes.get_last_error()}")
            exit_code = ws.wintypes.DWORD()
            if not self._kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(exit_code)):
                raise ws.WindowsSandboxError(f"GetExitCodeProcess failed: {ctypes.get_last_error()}")
            return int(exit_code.value)
        except WindowsJobError as exc:
            self._kernel32.TerminateProcess(info.hProcess, 125)
            raise ws.WindowsSandboxError(str(exc)) from exc
        finally:
            if job is not None:
                # KILL_ON_JOB_CLOSE cleans descendants even after the root exits.
                job.close()

    def _run_classic(
        self,
        *,
        command: list[str],
        workspace: Path,
        cwd: Path,
        allow_write: bool,
        allow_network: bool,
        isolated_home: Path,
        env: dict[str, str],
        timeout: int,
        max_output_bytes: int,
    ) -> ws.WindowsSandboxResult:
        import msvcrt

        workspace = workspace.resolve(strict=True)
        cwd = cwd.resolve(strict=True)
        isolated_home = isolated_home.resolve(strict=True)
        staged = isolated_home / "workspace"
        scratch = isolated_home / "scratch"
        scratch.mkdir(parents=True, exist_ok=True)
        shutil.copytree(workspace, staged, symlinks=True, dirs_exist_ok=True)
        try:
            assert_no_reparse_tree(staged)
        except WindowsPathError as exc:
            raise ws.WindowsSandboxError(str(exc)) from exc
        staged_cwd = staged / cwd.relative_to(workspace)

        mapped = ws._map_workspace_args(command, workspace, staged)
        proc_env = ws._safe_windows_env(env, scratch)
        executable = ws._resolve_executable(mapped, proc_env)
        mapped[0] = str(executable)

        identity = ws._identity(workspace)
        sid = ctypes.c_void_p()
        created = False
        attribute_list = None
        attribute_buffer = None
        allocations = []

        try:
            sid, created = self._create_profile(identity)
            self._grant_appcontainer_paths(
                root=isolated_home,
                staged=staged,
                scratch=scratch,
                sid_text=self._sid_string(sid),
                allow_write=allow_write,
            )
            capability_array, allocations = self._capabilities(allow_network)
            capabilities = ws.SECURITY_CAPABILITIES(
                sid,
                ctypes.cast(capability_array, ctypes.POINTER(ws.SID_AND_ATTRIBUTES)) if capability_array is not None else None,
                1 if capability_array is not None else 0,
                0,
            )

            output_path = isolated_home / "command-output.bin"
            with open(os.devnull, "rb", buffering=0) as stdin_handle, open(output_path, "w+b", buffering=0) as output_handle:
                os.set_inheritable(stdin_handle.fileno(), True)
                os.set_inheritable(output_handle.fileno(), True)
                stdin_os = ws.wintypes.HANDLE(msvcrt.get_osfhandle(stdin_handle.fileno()))
                output_os = ws.wintypes.HANDLE(msvcrt.get_osfhandle(output_handle.fileno()))
                handles = (ws.wintypes.HANDLE * 2)(stdin_os, output_os)

                size = ctypes.c_size_t(0)
                self._kernel32.InitializeProcThreadAttributeList(None, 2, 0, ctypes.byref(size))
                if not size.value:
                    raise ws.WindowsSandboxError("InitializeProcThreadAttributeList did not return a size")
                attribute_buffer = ctypes.create_string_buffer(size.value)
                attribute_list = ctypes.cast(attribute_buffer, ctypes.c_void_p)
                if not self._kernel32.InitializeProcThreadAttributeList(attribute_list, 2, 0, ctypes.byref(size)):
                    raise ws.WindowsSandboxError(f"InitializeProcThreadAttributeList failed: {ctypes.get_last_error()}")
                if not self._kernel32.UpdateProcThreadAttribute(
                    attribute_list, 0, ws._PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                    ctypes.byref(capabilities), ctypes.sizeof(capabilities), None, None,
                ):
                    raise ws.WindowsSandboxError(f"security-capabilities attribute failed: {ctypes.get_last_error()}")
                if not self._kernel32.UpdateProcThreadAttribute(
                    attribute_list, 0, ws._PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                    ctypes.cast(handles, ctypes.c_void_p), ctypes.sizeof(handles), None, None,
                ):
                    raise ws.WindowsSandboxError(f"handle-list attribute failed: {ctypes.get_last_error()}")

                startup = ws.STARTUPINFOEXW()
                startup.StartupInfo.cb = ctypes.sizeof(ws.STARTUPINFOEXW)
                startup.StartupInfo.dwFlags = ws._STARTF_USESTDHANDLES
                startup.StartupInfo.hStdInput = stdin_os
                startup.StartupInfo.hStdOutput = output_os
                startup.StartupInfo.hStdError = output_os
                startup.lpAttributeList = attribute_list

                command_line = ctypes.create_unicode_buffer(subprocess.list2cmdline(mapped))
                environment = self._classic_environment(env, scratch)
                info = ws.PROCESS_INFORMATION()
                ok = self._kernel32.CreateProcessW(
                    str(executable), command_line, None, None, True,
                    ws._CREATE_UNICODE_ENVIRONMENT | ws._CREATE_NO_WINDOW | ws._EXTENDED_STARTUPINFO_PRESENT | _CREATE_SUSPENDED,
                    ctypes.cast(environment, ctypes.c_void_p), str(staged_cwd),
                    ctypes.cast(ctypes.byref(startup), ctypes.POINTER(ws.STARTUPINFOW)), ctypes.byref(info),
                )
                if not ok:
                    raise ws.WindowsSandboxError(f"classic AppContainer CreateProcessW failed: {ctypes.get_last_error()}")
                try:
                    returncode = self._wait_in_job(info, timeout)
                finally:
                    self._kernel32.CloseHandle(info.hThread)
                    self._kernel32.CloseHandle(info.hProcess)
                output = ws._read_output(output_handle, max_output_bytes)

            if allow_write:
                try:
                    assert_no_reparse_tree(staged)
                except WindowsPathError as exc:
                    raise ws.WindowsSandboxError(str(exc)) from exc
                ws._sync_stage_back(staged, workspace)
            return ws.WindowsSandboxResult(returncode, output, "windows-appcontainer-classic-job")
        finally:
            if attribute_list is not None:
                try:
                    self._kernel32.DeleteProcThreadAttributeList(attribute_list)
                except Exception:
                    pass
            self._free_capabilities(allocations)
            if sid:
                self._advapi32.FreeSid(sid)
            if created:
                self._userenv.DeleteAppContainerProfile(identity)
