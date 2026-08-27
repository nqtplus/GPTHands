from __future__ import annotations

import ctypes
import hashlib
import os
import platform
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
_STARTF_USESTDHANDLES = 0x00000100
_WAIT_OBJECT_0 = 0x00000000
_WAIT_TIMEOUT = 0x00000102
_INFINITE = 0xFFFFFFFF


if platform.system() == "Windows":
    from ctypes import wintypes

    class STARTUPINFOW(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("lpReserved", wintypes.LPWSTR),
            ("lpDesktop", wintypes.LPWSTR),
            ("lpTitle", wintypes.LPWSTR),
            ("dwX", wintypes.DWORD),
            ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD),
            ("dwYSize", wintypes.DWORD),
            ("dwXCountChars", wintypes.DWORD),
            ("dwYCountChars", wintypes.DWORD),
            ("dwFillAttribute", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("wShowWindow", wintypes.WORD),
            ("cbReserved2", wintypes.WORD),
            ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
            ("hStdInput", wintypes.HANDLE),
            ("hStdOutput", wintypes.HANDLE),
            ("hStdError", wintypes.HANDLE),
        ]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE),
            ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD),
            ("dwThreadId", wintypes.DWORD),
        ]


@dataclass(frozen=True)
class WindowsSandboxResult:
    returncode: int
    output: bytes
    backend: str = "windows-appcontainer"


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


def build_sandbox_spec(
    *,
    read_write: Iterable[Path],
    read_only: Iterable[Path],
    allow_network: bool,
) -> bytes:
    """Build the minimal FlatBuffer SandboxSpec consumed by processmodel.dll.

    The wire slots follow Microsoft's public BaseContainerSpecification.fbs.
    Keeping this encoder local avoids adding a runtime FlatBuffers dependency.
    """

    # Header + vtable + padding. Root table starts at offset 40 so the uint64
    # UI-restrictions field is naturally aligned.
    root = 40
    vtable = 8
    object_size = 48
    field_count = 12
    buf = bytearray(root + object_size)
    struct.pack_into("<I", buf, 0, root)
    buf[4:8] = b"SBOX"

    offsets = [0] * field_count
    offsets[0] = 4   # version:string
    offsets[1] = 8   # app_container:bool
    offsets[3] = 9   # disallow_win32k_system_calls:bool
    offsets[4] = 16  # ui_restrictions:uint64
    offsets[5] = 24  # least_privilege:bool
    offsets[7] = 32  # fs_read_write:[string]
    offsets[8] = 36  # fs_read_only:[string]
    if allow_network:
        offsets[6] = 28  # capabilities:string

    vtable_size = 4 + field_count * 2
    struct.pack_into("<HH", buf, vtable, vtable_size, object_size)
    for index, offset in enumerate(offsets):
        struct.pack_into("<H", buf, vtable + 4 + index * 2, offset)

    struct.pack_into("<i", buf, root, root - vtable)
    buf[root + 8] = 1   # app_container
    buf[root + 9] = 1   # disallow_win32k_system_calls
    # Restrict USER subsystem interaction: handles, clipboard, system params,
    # display settings, global atoms, desktops, and ExitWindows.
    struct.pack_into("<Q", buf, root + 16, 0xFF)
    buf[root + 24] = 1  # least_privilege

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


def _environment_block(env: dict[str, str]) -> ctypes.Array[ctypes.c_wchar]:
    text = "\0".join(f"{key}={value}" for key, value in sorted(env.items(), key=lambda item: item[0].upper())) + "\0\0"
    return ctypes.create_unicode_buffer(text)


def _identity(workspace: Path) -> str:
    digest = hashlib.sha256(str(workspace.resolve()).encode("utf-8")).hexdigest()[:24]
    return f"GPTHands.{digest}"


class WindowsAppContainerSandbox:
    """Windows 11 AppContainer backend using processmodel.dll SandboxEngine.

    The API is intentionally loaded dynamically because Microsoft currently
    marks it experimental. Hosts without the export are treated as unsupported
    and callers must fail closed when OS sandboxing is required.
    """

    def __init__(self) -> None:
        if platform.system() != "Windows":
            raise WindowsSandboxError("Windows AppContainer backend is only available on Windows")
        try:
            self._dll = ctypes.WinDLL("processmodel.dll", use_last_error=True)
            self._create = getattr(self._dll, "Experimental_CreateProcessInSandbox")
        except (OSError, AttributeError) as exc:
            raise WindowsSandboxError("Windows AppContainer SandboxEngine API is unavailable") from exc

        self._kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
        self._create.restype = wintypes.BOOL
        self._create.argtypes = [
            wintypes.LPCWSTR,
            wintypes.LPWSTR,
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.BOOL,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.LPCWSTR,
            ctypes.POINTER(STARTUPINFOW),
            wintypes.LPCWSTR,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(PROCESS_INFORMATION),
        ]

    @staticmethod
    def available() -> bool:
        if platform.system() != "Windows":
            return False
        try:
            dll = ctypes.WinDLL("processmodel.dll", use_last_error=True)
            getattr(dll, "Experimental_CreateProcessInSandbox")
            return True
        except (OSError, AttributeError):
            return False

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
    ) -> WindowsSandboxResult:
        import msvcrt

        workspace = workspace.resolve(strict=True)
        cwd = cwd.resolve(strict=True)
        isolated_home = isolated_home.resolve(strict=True)
        executable = _resolve_executable(command, env)

        rw_paths = [isolated_home]
        ro_paths = [executable.parent]
        if allow_write:
            rw_paths.append(workspace)
        else:
            ro_paths.append(workspace)

        spec = build_sandbox_spec(read_write=rw_paths, read_only=ro_paths, allow_network=allow_network)
        spec_buffer = ctypes.create_string_buffer(spec)
        command_line = ctypes.create_unicode_buffer(subprocess.list2cmdline([str(executable), *command[1:]]))
        environment = _environment_block(env)

        output_path = isolated_home / "command-output.bin"
        with open(os.devnull, "rb", buffering=0) as stdin_handle, open(output_path, "w+b", buffering=0) as output_handle:
            os.set_inheritable(stdin_handle.fileno(), True)
            os.set_inheritable(output_handle.fileno(), True)
            startup = STARTUPINFOW()
            startup.cb = ctypes.sizeof(STARTUPINFOW)
            startup.dwFlags = _STARTF_USESTDHANDLES
            startup.hStdInput = wintypes.HANDLE(msvcrt.get_osfhandle(stdin_handle.fileno()))
            startup.hStdOutput = wintypes.HANDLE(msvcrt.get_osfhandle(output_handle.fileno()))
            startup.hStdError = wintypes.HANDLE(msvcrt.get_osfhandle(output_handle.fileno()))
            info = PROCESS_INFORMATION()

            ok = self._create(
                str(executable),
                command_line,
                None,
                None,
                False,
                _CREATE_UNICODE_ENVIRONMENT | _CREATE_NO_WINDOW,
                ctypes.cast(environment, ctypes.c_void_p),
                str(cwd),
                ctypes.byref(startup),
                _identity(workspace),
                ctypes.cast(spec_buffer, ctypes.c_void_p),
                len(spec),
                ctypes.byref(info),
            )
            if not ok:
                error = ctypes.get_last_error()
                raise WindowsSandboxError(f"CreateProcessInSandbox failed with Win32 error {error}")

            try:
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
            finally:
                self._kernel32.CloseHandle(info.hThread)
                self._kernel32.CloseHandle(info.hProcess)

            output_handle.flush()
            output_handle.seek(0)
            output = output_handle.read(max_output_bytes + 1)

        if len(output) > max_output_bytes:
            output = output[:max_output_bytes] + b"\n[output truncated by GPTHands policy]"
        return WindowsSandboxResult(returncode=int(exit_code.value), output=output)
