from __future__ import annotations

import ctypes
import platform
from dataclasses import dataclass


class WindowsJobError(RuntimeError):
    pass


_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9


if platform.system() == "Windows":
    from ctypes import wintypes

    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]


@dataclass
class WindowsJobObject:
    """Owner-side Job Object used to contain an AppContainer process tree.

    KILL_ON_JOB_CLOSE ensures descendants cannot outlive the GPTHands action.
    ActiveProcessLimit bounds fork/spawn fan-out without relying on model intent.
    """

    handle: int
    kernel32: object

    @classmethod
    def create(cls, *, max_processes: int = 32) -> "WindowsJobObject":
        if platform.system() != "Windows":
            raise WindowsJobError("Windows Job Objects are only available on Windows")
        if not 1 <= max_processes <= 256:
            raise WindowsJobError("max_processes must be between 1 and 256")
        kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel32.TerminateJobObject.restype = wintypes.BOOL
        kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel32.IsProcessInJob.restype = wintypes.BOOL
        kernel32.IsProcessInJob.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            raise WindowsJobError(f"CreateJobObjectW failed: {ctypes.get_last_error()}")
        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | _JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        info.BasicLimitInformation.ActiveProcessLimit = max_processes
        if not kernel32.SetInformationJobObject(
            handle,
            _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(info),
            ctypes.sizeof(info),
        ):
            error = ctypes.get_last_error()
            kernel32.CloseHandle(handle)
            raise WindowsJobError(f"SetInformationJobObject failed: {error}")
        return cls(int(handle), kernel32)

    def assign(self, process_handle: int) -> None:
        if not self.handle:
            raise WindowsJobError("job object is closed")
        if not self.kernel32.AssignProcessToJobObject(self.handle, process_handle):
            raise WindowsJobError(f"AssignProcessToJobObject failed: {ctypes.get_last_error()}")
        inside = wintypes.BOOL()
        if not self.kernel32.IsProcessInJob(process_handle, self.handle, ctypes.byref(inside)) or not inside.value:
            raise WindowsJobError("process was not contained by the GPTHands Job Object")

    def terminate(self, exit_code: int = 124) -> None:
        if self.handle and not self.kernel32.TerminateJobObject(self.handle, exit_code):
            raise WindowsJobError(f"TerminateJobObject failed: {ctypes.get_last_error()}")

    def close(self) -> None:
        if self.handle:
            self.kernel32.CloseHandle(self.handle)
            self.handle = 0

    def __enter__(self) -> "WindowsJobObject":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
