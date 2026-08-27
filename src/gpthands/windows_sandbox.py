from __future__ import annotations

import ctypes
import hashlib
import os
import platform
import secrets
import shutil
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


class WindowsSandboxError(RuntimeError):
    pass


_CREATE_UNICODE_ENVIRONMENT = 0x00000400
_CREATE_NO_WINDOW = 0x08000000
_EXTENDED_STARTUPINFO_PRESENT = 0x00080000
_STARTF_USESTDHANDLES = 0x00000100
_WAIT_OBJECT_0 = 0x00000000
_WAIT_TIMEOUT = 0x00000102
_PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
_PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
_SE_GROUP_ENABLED = 0x00000004
_ERROR_ALREADY_EXISTS_HRESULT = 0x800700B7


if platform.system() == "Windows":
    from ctypes import wintypes

    class STARTUPINFOW(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
            ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
            ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
            ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
            ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
            ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
            ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
            ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE),
            ("hStdError", wintypes.HANDLE),
        ]

    class STARTUPINFOEXW(ctypes.Structure):
        _fields_ = [("StartupInfo", STARTUPINFOW), ("lpAttributeList", ctypes.c_void_p)]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD),
        ]

    class SID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

    class SECURITY_CAPABILITIES(ctypes.Structure):
        _fields_ = [
            ("AppContainerSid", ctypes.c_void_p),
            ("Capabilities", ctypes.POINTER(SID_AND_ATTRIBUTES)),
            ("CapabilityCount", wintypes.DWORD),
            ("Reserved", wintypes.DWORD),
        ]


@dataclass(frozen=True)
class WindowsSandboxResult:
    returncode: int
    output: bytes
    backend: str


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _append_string(buf: bytearray, value: str) -> int:
    encoded = value.encode("utf-8")
    pos = _align(len(buf), 4)
    if pos > len(buf):
        buf.extend(b"\x00" * (pos - len(buf)))
    buf.extend(struct.pack("<I", len(encoded)))
    buf.extend(encoded)
    buf.append(0)
    while len(buf) % 4:
        buf.append(0)
    return pos


def _append_string_vector(buf: bytearray, values: Iterable[str]) -> int:
    items = list(values)
    pos = _align(len(buf), 4)
    if pos > len(buf):
        buf.extend(b"\x00" * (pos - len(buf)))
    buf.extend(struct.pack("<I", len(items)))
    slots: list[int] = []
    for _ in items:
        slots.append(len(buf))
        buf.extend(b"\x00\x00\x00\x00")
    for slot, value in zip(slots, items):
        target = _append_string(buf, value)
        struct.pack_into("<I", buf, slot, target - slot)
    return pos


def build_sandbox_spec(*, read_write: Iterable[Path], read_only: Iterable[Path], allow_network: bool) -> bytes:
    """Build the minimal Microsoft SandboxSpec FlatBuffer without dependencies."""
    root, vtable, object_size, field_count = 40, 8, 48, 12
    buf = bytearray(root + object_size)
    struct.pack_into("<I", buf, 0, root)
    buf[4:8] = b"SBOX"
    offsets = [0] * field_count
    for index, offset in {0: 4, 1: 8, 3: 9, 4: 16, 5: 24, 7: 32, 8: 36}.items():
        offsets[index] = offset
    if allow_network:
        offsets[6] = 28
    struct.pack_into("<HH", buf, vtable, 4 + field_count * 2, object_size)
    for index, offset in enumerate(offsets):
        struct.pack_into("<H", buf, vtable + 4 + index * 2, offset)
    struct.pack_into("<i", buf, root, root - vtable)
    buf[root + 8] = 1
    buf[root + 9] = 1
    struct.pack_into("<Q", buf, root + 16, 0xFF)
    buf[root + 24] = 1
    version = _append_string(buf, "0.1.0")
    struct.pack_into("<I", buf, root + 4, version - (root + 4))
    if allow_network:
        capabilities = _append_string(buf, "internetClient")
        struct.pack_into("<I", buf, root + 28, capabilities - (root + 28))
    rw = _append_string_vector(buf, [str(Path(p).resolve()) for p in read_write])
    ro = _append_string_vector(buf, [str(Path(p).resolve()) for p in read_only])
    struct.pack_into("<I", buf, root + 32, rw - (root + 32))
    struct.pack_into("<I", buf, root + 36, ro - (root + 36))
    return bytes(buf)


def _resolve_executable(command: list[str], env: dict[str, str]) -> Path:
    if not command:
        raise WindowsSandboxError("empty command")
    candidate = Path(command[0])
    if candidate.is_absolute() and candidate.exists():
        return candidate.resolve()
    found = shutil.which(command[0], path=env.get("PATH"))
    if not found:
        raise WindowsSandboxError(f"Windows sandbox executable not found: {command[0]}")
    return Path(found).resolve()


def _safe_windows_env(env: dict[str, str], isolated_home: Path) -> dict[str, str]:
    result = dict(env)
    for name in ("SystemRoot", "WINDIR", "PATHEXT", "COMSPEC"):
        value = os.environ.get(name)
        if value:
            result.setdefault(name, value)
    home = str(isolated_home)
    result.update({"TEMP": home, "TMP": home, "USERPROFILE": home, "HOME": home})
    return result


def _environment_block(env: dict[str, str]) -> ctypes.Array[ctypes.c_wchar]:
    text = "\0".join(f"{key}={value}" for key, value in sorted(env.items(), key=lambda item: item[0].upper())) + "\0\0"
    return ctypes.create_unicode_buffer(text)


def _identity(workspace: Path) -> str:
    digest = hashlib.sha256(str(workspace.resolve()).encode("utf-8")).hexdigest()[:16]
    return f"GPTHands.{digest}.{secrets.token_hex(6)}"


def _inside(root: Path, candidate: Path) -> bool:
    try:
        return os.path.commonpath((str(root), str(candidate))) == str(root)
    except ValueError:
        return False


def _map_workspace_args(command: list[str], workspace: Path, staged: Path) -> list[str]:
    mapped: list[str] = []
    for value in command:
        try:
            candidate = Path(value)
            if candidate.is_absolute():
                resolved = candidate.resolve(strict=False)
                if _inside(workspace, resolved):
                    mapped.append(str(staged / resolved.relative_to(workspace)))
                    continue
        except (OSError, ValueError):
            pass
        mapped.append(value)
    return mapped


def _sync_stage_back(staged: Path, workspace: Path) -> None:
    for source in staged.rglob("*"):
        relative = source.relative_to(staged)
        target = workspace / relative
        if source.is_symlink():
            continue
        if source.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif source.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)


def _read_output(handle, max_output_bytes: int) -> bytes:
    handle.flush()
    handle.seek(0)
    output = handle.read(max_output_bytes + 1)
    if len(output) > max_output_bytes:
        return output[:max_output_bytes] + b"\n[output truncated by GPTHands policy]"
    return output


class WindowsAppContainerSandbox:
    """Real Windows AppContainer process isolation.

    Windows 11 SandboxEngine is preferred. A stable classic AppContainer
    implementation is used on Windows Server/older SKUs. Neither path can
    silently degrade to policy-only execution.
    """

    def __init__(self) -> None:
        if platform.system() != "Windows":
            raise WindowsSandboxError("Windows AppContainer backend is only available on Windows")
        self._kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
        self._modern = None
        try:
            dll = ctypes.WinDLL("processmodel.dll", use_last_error=True)
            modern = getattr(dll, "Experimental_CreateProcessInSandbox")
            modern.restype = wintypes.BOOL
            modern.argtypes = [
                wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
                wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
                ctypes.POINTER(STARTUPINFOW), wintypes.LPCWSTR, ctypes.c_void_p,
                wintypes.DWORD, ctypes.POINTER(PROCESS_INFORMATION),
            ]
            self._modern = modern
        except (OSError, AttributeError):
            pass
        try:
            self._userenv = ctypes.WinDLL("userenv.dll", use_last_error=True)
            self._advapi32 = ctypes.WinDLL("advapi32.dll", use_last_error=True)
            self._kernelbase = ctypes.WinDLL("KernelBase.dll", use_last_error=True)
            self._configure_classic_apis()
            self._classic_available = True
        except (OSError, AttributeError):
            self._classic_available = False
        if self._modern is None and not self._classic_available:
            raise WindowsSandboxError("no Windows AppContainer process-creation backend is available")

    def _configure_classic_apis(self) -> None:
        self._userenv.CreateAppContainerProfile.restype = ctypes.c_long
        self._userenv.CreateAppContainerProfile.argtypes = [
            wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
            ctypes.POINTER(SID_AND_ATTRIBUTES), wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
        ]
        self._userenv.DeriveAppContainerSidFromAppContainerName.restype = ctypes.c_long
        self._userenv.DeriveAppContainerSidFromAppContainerName.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
        self._userenv.DeleteAppContainerProfile.restype = ctypes.c_long
        self._userenv.DeleteAppContainerProfile.argtypes = [wintypes.LPCWSTR]
        self._advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
        self._advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
        self._advapi32.FreeSid.restype = ctypes.c_void_p
        self._advapi32.FreeSid.argtypes = [ctypes.c_void_p]
        self._kernel32.LocalFree.restype = ctypes.c_void_p
        self._kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        self._kernel32.InitializeProcThreadAttributeList.restype = wintypes.BOOL
        self._kernel32.InitializeProcThreadAttributeList.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.c_size_t)]
        self._kernel32.UpdateProcThreadAttribute.restype = wintypes.BOOL
        self._kernel32.UpdateProcThreadAttribute.argtypes = [
            ctypes.c_void_p, wintypes.DWORD, ctypes.c_size_t, ctypes.c_void_p,
            ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p,
        ]
        self._kernel32.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]
        self._kernel32.CreateProcessW.restype = wintypes.BOOL
        self._kernel32.CreateProcessW.argtypes = [
            wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
            wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
            ctypes.POINTER(STARTUPINFOW), ctypes.POINTER(PROCESS_INFORMATION),
        ]
        self._kernelbase.DeriveCapabilitySidsFromName.restype = wintypes.BOOL
        self._kernelbase.DeriveCapabilitySidsFromName.argtypes = [
            wintypes.LPCWSTR, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)), ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)), ctypes.POINTER(wintypes.DWORD),
        ]

    @staticmethod
    def available() -> bool:
        if platform.system() != "Windows":
            return False
        try:
            userenv = ctypes.WinDLL("userenv.dll", use_last_error=True)
            kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
            getattr(userenv, "CreateAppContainerProfile")
            getattr(kernel32, "UpdateProcThreadAttribute")
            return True
        except (OSError, AttributeError):
            return False

    def run(self, *, command: list[str], workspace: Path, cwd: Path, allow_write: bool,
            allow_network: bool, isolated_home: Path, env: dict[str, str], timeout: int,
            max_output_bytes: int) -> WindowsSandboxResult:
        if self._modern is not None:
            try:
                return self._run_modern(command=command, workspace=workspace, cwd=cwd,
                    allow_write=allow_write, allow_network=allow_network, isolated_home=isolated_home,
                    env=env, timeout=timeout, max_output_bytes=max_output_bytes)
            except WindowsSandboxError:
                if not self._classic_available:
                    raise
        if not self._classic_available:
            raise WindowsSandboxError("classic Windows AppContainer backend is unavailable")
        return self._run_classic(command=command, workspace=workspace, cwd=cwd,
            allow_write=allow_write, allow_network=allow_network, isolated_home=isolated_home,
            env=env, timeout=timeout, max_output_bytes=max_output_bytes)

    def _wait_process(self, info: PROCESS_INFORMATION, timeout: int) -> int:
        wait = self._kernel32.WaitForSingleObject(info.hProcess, max(1, timeout) * 1000)
        if wait == _WAIT_TIMEOUT:
            self._kernel32.TerminateProcess(info.hProcess, 124)
            self._kernel32.WaitForSingleObject(info.hProcess, 5000)
            raise WindowsSandboxError(f"command exceeded {timeout}s timeout")
        if wait != _WAIT_OBJECT_0:
            raise WindowsSandboxError(f"WaitForSingleObject failed: {ctypes.get_last_error()}")
        exit_code = wintypes.DWORD()
        if not self._kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(exit_code)):
            raise WindowsSandboxError(f"GetExitCodeProcess failed: {ctypes.get_last_error()}")
        return int(exit_code.value)

    def _run_modern(self, *, command: list[str], workspace: Path, cwd: Path, allow_write: bool,
                    allow_network: bool, isolated_home: Path, env: dict[str, str], timeout: int,
                    max_output_bytes: int) -> WindowsSandboxResult:
        import msvcrt
        workspace, cwd, isolated_home = workspace.resolve(strict=True), cwd.resolve(strict=True), isolated_home.resolve(strict=True)
        proc_env = _safe_windows_env(env, isolated_home)
        executable = _resolve_executable(command, proc_env)
        rw_paths, ro_paths = [isolated_home], [executable.parent]
        (rw_paths if allow_write else ro_paths).append(workspace)
        spec = build_sandbox_spec(read_write=rw_paths, read_only=ro_paths, allow_network=allow_network)
        spec_buffer = ctypes.create_string_buffer(spec)
        command_line = ctypes.create_unicode_buffer(subprocess.list2cmdline([str(executable), *command[1:]]))
        environment = _environment_block(proc_env)
        output_path = isolated_home / "command-output.bin"
        with open(os.devnull, "rb", buffering=0) as stdin_handle, open(output_path, "w+b", buffering=0) as output_handle:
            os.set_inheritable(stdin_handle.fileno(), True); os.set_inheritable(output_handle.fileno(), True)
            startup = STARTUPINFOW(); startup.cb = ctypes.sizeof(STARTUPINFOW); startup.dwFlags = _STARTF_USESTDHANDLES
            startup.hStdInput = wintypes.HANDLE(msvcrt.get_osfhandle(stdin_handle.fileno()))
            startup.hStdOutput = wintypes.HANDLE(msvcrt.get_osfhandle(output_handle.fileno())); startup.hStdError = startup.hStdOutput
            info = PROCESS_INFORMATION()
            ok = self._modern(str(executable), command_line, None, None, False,
                _CREATE_UNICODE_ENVIRONMENT | _CREATE_NO_WINDOW, ctypes.cast(environment, ctypes.c_void_p),
                str(cwd), ctypes.byref(startup), _identity(workspace), ctypes.cast(spec_buffer, ctypes.c_void_p),
                len(spec), ctypes.byref(info))
            if not ok:
                raise WindowsSandboxError(f"CreateProcessInSandbox failed with Win32 error {ctypes.get_last_error()}")
            try: returncode = self._wait_process(info, timeout)
            finally:
                self._kernel32.CloseHandle(info.hThread); self._kernel32.CloseHandle(info.hProcess)
            output = _read_output(output_handle, max_output_bytes)
        return WindowsSandboxResult(returncode, output, "windows-appcontainer-sandboxengine")

    def _create_profile(self, identity: str) -> tuple[ctypes.c_void_p, bool]:
        sid = ctypes.c_void_p()
        hr = self._userenv.CreateAppContainerProfile(identity, "GPTHands sandbox", "Ephemeral GPTHands AppContainer", None, 0, ctypes.byref(sid))
        unsigned = ctypes.c_ulong(hr).value
        if hr == 0: return sid, True
        if unsigned == _ERROR_ALREADY_EXISTS_HRESULT:
            hr = self._userenv.DeriveAppContainerSidFromAppContainerName(identity, ctypes.byref(sid))
            if hr == 0: return sid, False
        raise WindowsSandboxError(f"CreateAppContainerProfile failed with HRESULT 0x{unsigned:08x}")

    def _sid_string(self, sid: ctypes.c_void_p) -> str:
        value = wintypes.LPWSTR()
        if not self._advapi32.ConvertSidToStringSidW(sid, ctypes.byref(value)):
            raise WindowsSandboxError(f"ConvertSidToStringSid failed: {ctypes.get_last_error()}")
        try: return value.value
        finally: self._kernel32.LocalFree(ctypes.cast(value, ctypes.c_void_p))

    def _grant_staging_access(self, path: Path, sid_text: str) -> None:
        grant = subprocess.run(["icacls.exe", str(path), "/grant", f"*{sid_text}:(OI)(CI)M", "/T", "/C", "/Q"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=False, check=False)
        if grant.returncode != 0:
            raise WindowsSandboxError(f"icacls AppContainer grant failed: {grant.stdout.decode(errors='replace')[:500]}")
        integrity = subprocess.run(["icacls.exe", str(path), "/setintegritylevel", "(OI)(CI)L", "/T", "/C", "/Q"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=False, check=False)
        if integrity.returncode != 0:
            raise WindowsSandboxError(f"icacls low-integrity label failed: {integrity.stdout.decode(errors='replace')[:500]}")

    def _capabilities(self, allow_network: bool):
        if not allow_network: return None, []
        groups = ctypes.POINTER(ctypes.c_void_p)(); group_count = wintypes.DWORD()
        caps = ctypes.POINTER(ctypes.c_void_p)(); cap_count = wintypes.DWORD()
        if not self._kernelbase.DeriveCapabilitySidsFromName("internetClient", ctypes.byref(groups), ctypes.byref(group_count), ctypes.byref(caps), ctypes.byref(cap_count)):
            raise WindowsSandboxError(f"DeriveCapabilitySidsFromName failed: {ctypes.get_last_error()}")
        if cap_count.value < 1: raise WindowsSandboxError("internetClient capability SID was not returned")
        array = (SID_AND_ATTRIBUTES * 1)(); array[0].Sid = caps[0]; array[0].Attributes = _SE_GROUP_ENABLED
        return array, [(groups, group_count.value), (caps, cap_count.value)]

    def _free_capabilities(self, allocations) -> None:
        for array, count in allocations:
            if not array: continue
            for index in range(count):
                if array[index]: self._kernel32.LocalFree(array[index])
            self._kernel32.LocalFree(ctypes.cast(array, ctypes.c_void_p))

    def _run_classic(self, *, command: list[str], workspace: Path, cwd: Path, allow_write: bool,
                     allow_network: bool, isolated_home: Path, env: dict[str, str], timeout: int,
                     max_output_bytes: int) -> WindowsSandboxResult:
        import msvcrt
        workspace, cwd, isolated_home = workspace.resolve(strict=True), cwd.resolve(strict=True), isolated_home.resolve(strict=True)
        staged = isolated_home / "workspace"
        shutil.copytree(workspace, staged, symlinks=True, dirs_exist_ok=True)
        staged_cwd = staged / cwd.relative_to(workspace)
        mapped = _map_workspace_args(command, workspace, staged)
        proc_env = _safe_windows_env(env, isolated_home)
        executable = _resolve_executable(mapped, proc_env); mapped[0] = str(executable)
        identity = _identity(workspace); sid = ctypes.c_void_p(); created = False; attribute_list = None; allocations = []
        try:
            sid, created = self._create_profile(identity)
            self._grant_staging_access(isolated_home, self._sid_string(sid))
            capability_array, allocations = self._capabilities(allow_network)
            capabilities = SECURITY_CAPABILITIES(sid,
                ctypes.cast(capability_array, ctypes.POINTER(SID_AND_ATTRIBUTES)) if capability_array is not None else None,
                1 if capability_array is not None else 0, 0)
            output_path = isolated_home / "command-output.bin"
            with open(os.devnull, "rb", buffering=0) as stdin_handle, open(output_path, "w+b", buffering=0) as output_handle:
                os.set_inheritable(stdin_handle.fileno(), True); os.set_inheritable(output_handle.fileno(), True)
                handles = (wintypes.HANDLE * 3)(wintypes.HANDLE(msvcrt.get_osfhandle(stdin_handle.fileno())),
                    wintypes.HANDLE(msvcrt.get_osfhandle(output_handle.fileno())), wintypes.HANDLE(msvcrt.get_osfhandle(output_handle.fileno())))
                size = ctypes.c_size_t(0); self._kernel32.InitializeProcThreadAttributeList(None, 2, 0, ctypes.byref(size))
                if not size.value: raise WindowsSandboxError("InitializeProcThreadAttributeList did not return a size")
                buffer = ctypes.create_string_buffer(size.value); attribute_list = ctypes.cast(buffer, ctypes.c_void_p)
                if not self._kernel32.InitializeProcThreadAttributeList(attribute_list, 2, 0, ctypes.byref(size)):
                    raise WindowsSandboxError(f"InitializeProcThreadAttributeList failed: {ctypes.get_last_error()}")
                if not self._kernel32.UpdateProcThreadAttribute(attribute_list, 0, _PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                    ctypes.byref(capabilities), ctypes.sizeof(capabilities), None, None):
                    raise WindowsSandboxError(f"security-capabilities attribute failed: {ctypes.get_last_error()}")
                if not self._kernel32.UpdateProcThreadAttribute(attribute_list, 0, _PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                    ctypes.cast(handles, ctypes.c_void_p), ctypes.sizeof(handles), None, None):
                    raise WindowsSandboxError(f"handle-list attribute failed: {ctypes.get_last_error()}")
                startup = STARTUPINFOEXW(); startup.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEXW); startup.StartupInfo.dwFlags = _STARTF_USESTDHANDLES
                startup.StartupInfo.hStdInput, startup.StartupInfo.hStdOutput, startup.StartupInfo.hStdError = handles[0], handles[1], handles[2]
                startup.lpAttributeList = attribute_list
                command_line = ctypes.create_unicode_buffer(subprocess.list2cmdline(mapped)); environment = _environment_block(proc_env); info = PROCESS_INFORMATION()
                ok = self._kernel32.CreateProcessW(str(executable), command_line, None, None, True,
                    _CREATE_UNICODE_ENVIRONMENT | _CREATE_NO_WINDOW | _EXTENDED_STARTUPINFO_PRESENT,
                    ctypes.cast(environment, ctypes.c_void_p), str(staged_cwd),
                    ctypes.cast(ctypes.byref(startup), ctypes.POINTER(STARTUPINFOW)), ctypes.byref(info))
                if not ok: raise WindowsSandboxError(f"classic AppContainer CreateProcessW failed: {ctypes.get_last_error()}")
                try: returncode = self._wait_process(info, timeout)
                finally:
                    self._kernel32.CloseHandle(info.hThread); self._kernel32.CloseHandle(info.hProcess)
                output = _read_output(output_handle, max_output_bytes)
            if allow_write: _sync_stage_back(staged, workspace)
            return WindowsSandboxResult(returncode, output, "windows-appcontainer-classic")
        finally:
            if attribute_list is not None:
                try: self._kernel32.DeleteProcThreadAttributeList(attribute_list)
                except Exception: pass
            self._free_capabilities(allocations)
            if sid: self._advapi32.FreeSid(sid)
            if created: self._userenv.DeleteAppContainerProfile(identity)
