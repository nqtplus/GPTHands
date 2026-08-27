from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
from pathlib import Path

from . import windows_sandbox as ws


class WindowsAppContainerSandbox(ws.WindowsAppContainerSandbox):
    """Windows backend with a hardened classic-AppContainer launch path.

    `CreateProcessW` requires LOCALAPPDATA when it resolves the per-user
    AppContainer profile. We copy only that required path plus GPTHands' small
    allowlisted environment into the child block; arbitrary host environment
    variables are never inherited.
    """

    @staticmethod
    def _classic_environment(env: dict[str, str], isolated_home: Path):
        values = ws._safe_windows_env(env, isolated_home)
        local_app_data = os.environ.get("LOCALAPPDATA")
        if not local_app_data:
            raise ws.WindowsSandboxError("LOCALAPPDATA is required to launch a classic Windows AppContainer")
        values["LOCALAPPDATA"] = local_app_data
        system_drive = os.environ.get("SystemDrive")
        if system_drive:
            values.setdefault("SystemDrive", system_drive)
        return ws._environment_block(values)

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
        shutil.copytree(workspace, staged, symlinks=True, dirs_exist_ok=True)
        staged_cwd = staged / cwd.relative_to(workspace)

        mapped = ws._map_workspace_args(command, workspace, staged)
        proc_env = ws._safe_windows_env(env, isolated_home)
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
            self._grant_staging_access(isolated_home, self._sid_string(sid))
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
                handles = (ws.wintypes.HANDLE * 3)(
                    ws.wintypes.HANDLE(msvcrt.get_osfhandle(stdin_handle.fileno())),
                    ws.wintypes.HANDLE(msvcrt.get_osfhandle(output_handle.fileno())),
                    ws.wintypes.HANDLE(msvcrt.get_osfhandle(output_handle.fileno())),
                )

                size = ctypes.c_size_t(0)
                self._kernel32.InitializeProcThreadAttributeList(None, 2, 0, ctypes.byref(size))
                if not size.value:
                    raise ws.WindowsSandboxError("InitializeProcThreadAttributeList did not return a size")
                attribute_buffer = ctypes.create_string_buffer(size.value)
                attribute_list = ctypes.cast(attribute_buffer, ctypes.c_void_p)
                if not self._kernel32.InitializeProcThreadAttributeList(attribute_list, 2, 0, ctypes.byref(size)):
                    raise ws.WindowsSandboxError(f"InitializeProcThreadAttributeList failed: {ctypes.get_last_error()}")
                if not self._kernel32.UpdateProcThreadAttribute(
                    attribute_list,
                    0,
                    ws._PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                    ctypes.byref(capabilities),
                    ctypes.sizeof(capabilities),
                    None,
                    None,
                ):
                    raise ws.WindowsSandboxError(f"security-capabilities attribute failed: {ctypes.get_last_error()}")
                if not self._kernel32.UpdateProcThreadAttribute(
                    attribute_list,
                    0,
                    ws._PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                    ctypes.cast(handles, ctypes.c_void_p),
                    ctypes.sizeof(handles),
                    None,
                    None,
                ):
                    raise ws.WindowsSandboxError(f"handle-list attribute failed: {ctypes.get_last_error()}")

                startup = ws.STARTUPINFOEXW()
                startup.StartupInfo.cb = ctypes.sizeof(ws.STARTUPINFOEXW)
                startup.StartupInfo.dwFlags = ws._STARTF_USESTDHANDLES
                startup.StartupInfo.hStdInput = handles[0]
                startup.StartupInfo.hStdOutput = handles[1]
                startup.StartupInfo.hStdError = handles[2]
                startup.lpAttributeList = attribute_list

                command_line = ctypes.create_unicode_buffer(subprocess.list2cmdline(mapped))
                environment = self._classic_environment(env, isolated_home)
                info = ws.PROCESS_INFORMATION()
                ok = self._kernel32.CreateProcessW(
                    str(executable),
                    command_line,
                    None,
                    None,
                    True,
                    ws._CREATE_UNICODE_ENVIRONMENT | ws._CREATE_NO_WINDOW | ws._EXTENDED_STARTUPINFO_PRESENT,
                    ctypes.cast(environment, ctypes.c_void_p),
                    str(staged_cwd),
                    ctypes.cast(ctypes.byref(startup), ctypes.POINTER(ws.STARTUPINFOW)),
                    ctypes.byref(info),
                )
                if not ok:
                    raise ws.WindowsSandboxError(f"classic AppContainer CreateProcessW failed: {ctypes.get_last_error()}")
                try:
                    returncode = self._wait_process(info, timeout)
                finally:
                    self._kernel32.CloseHandle(info.hThread)
                    self._kernel32.CloseHandle(info.hProcess)
                output = ws._read_output(output_handle, max_output_bytes)

            if allow_write:
                ws._sync_stage_back(staged, workspace)
            return ws.WindowsSandboxResult(returncode, output, "windows-appcontainer-classic")
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
