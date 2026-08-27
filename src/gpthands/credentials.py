from __future__ import annotations

import ctypes
import os
import platform
import shutil
import subprocess
from pathlib import Path


class CredentialStoreError(RuntimeError):
    pass


SERVICE = "GPTHands"


def _name(value: str) -> str:
    value = value.strip()
    if not value or len(value) > 128 or any(ch in value for ch in "\r\n\x00"):
        raise CredentialStoreError("credential name is invalid")
    return value


class CredentialStore:
    """OS-backed secret storage. There is intentionally no plaintext fallback."""

    def backend(self) -> str:
        system = platform.system()
        if system == "Darwin" and shutil.which("security"):
            return "macos-keychain"
        if system == "Windows":
            return "windows-credential-manager"
        if system == "Linux" and shutil.which("secret-tool"):
            return "linux-secret-service"
        raise CredentialStoreError("no supported OS credential store is available")

    def set(self, name: str, secret: str) -> None:
        name = _name(name)
        if not secret or "\x00" in secret:
            raise CredentialStoreError("credential value is invalid")
        backend = self.backend()
        if backend == "macos-keychain":
            self._mac_set(name, secret)
        elif backend == "windows-credential-manager":
            self._win_set(name, secret)
        else:
            self._linux_set(name, secret)

    def get(self, name: str) -> str:
        name = _name(name)
        backend = self.backend()
        if backend == "macos-keychain":
            return self._mac_get(name)
        if backend == "windows-credential-manager":
            return self._win_get(name)
        return self._linux_get(name)

    def delete(self, name: str) -> bool:
        name = _name(name)
        backend = self.backend()
        if backend == "macos-keychain":
            return self._mac_delete(name)
        if backend == "windows-credential-manager":
            return self._win_delete(name)
        return self._linux_delete(name)

    @staticmethod
    def _mac_set(name: str, secret: str) -> None:
        proc = subprocess.run(
            ["security", "add-generic-password", "-U", "-a", name, "-s", SERVICE, "-w", secret],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
        )
        if proc.returncode != 0:
            raise CredentialStoreError(f"Keychain write failed: {proc.stderr.strip()[:300]}")

    @staticmethod
    def _mac_get(name: str) -> str:
        proc = subprocess.run(
            ["security", "find-generic-password", "-a", name, "-s", SERVICE, "-w"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
        )
        if proc.returncode != 0:
            raise CredentialStoreError("credential not found in Keychain")
        return proc.stdout.rstrip("\n")

    @staticmethod
    def _mac_delete(name: str) -> bool:
        proc = subprocess.run(
            ["security", "delete-generic-password", "-a", name, "-s", SERVICE],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
        )
        return proc.returncode == 0

    @staticmethod
    def _linux_set(name: str, secret: str) -> None:
        proc = subprocess.run(
            ["secret-tool", "store", "--label", f"GPTHands {name}", "service", SERVICE, "name", name],
            input=secret,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
        )
        if proc.returncode != 0:
            raise CredentialStoreError(f"Secret Service write failed: {proc.stderr.strip()[:300]}")

    @staticmethod
    def _linux_get(name: str) -> str:
        proc = subprocess.run(
            ["secret-tool", "lookup", "service", SERVICE, "name", name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
        )
        value = proc.stdout.rstrip("\n")
        if proc.returncode != 0 or not value:
            raise CredentialStoreError("credential not found in Secret Service")
        return value

    @staticmethod
    def _linux_delete(name: str) -> bool:
        proc = subprocess.run(
            ["secret-tool", "clear", "service", SERVICE, "name", name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
        )
        return proc.returncode == 0

    @staticmethod
    def _win_api():
        from ctypes import wintypes

        CRED_TYPE_GENERIC = 1
        CRED_PERSIST_LOCAL_MACHINE = 2

        class CREDENTIALW(ctypes.Structure):
            _fields_ = [
                ("Flags", wintypes.DWORD),
                ("Type", wintypes.DWORD),
                ("TargetName", wintypes.LPWSTR),
                ("Comment", wintypes.LPWSTR),
                ("LastWritten", wintypes.FILETIME),
                ("CredentialBlobSize", wintypes.DWORD),
                ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
                ("Persist", wintypes.DWORD),
                ("AttributeCount", wintypes.DWORD),
                ("Attributes", ctypes.c_void_p),
                ("TargetAlias", wintypes.LPWSTR),
                ("UserName", wintypes.LPWSTR),
            ]

        advapi = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
        advapi.CredWriteW.restype = wintypes.BOOL
        advapi.CredWriteW.argtypes = [ctypes.POINTER(CREDENTIALW), wintypes.DWORD]
        advapi.CredReadW.restype = wintypes.BOOL
        advapi.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.POINTER(CREDENTIALW))]
        advapi.CredDeleteW.restype = wintypes.BOOL
        advapi.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
        advapi.CredFree.argtypes = [ctypes.c_void_p]
        return advapi, CREDENTIALW, CRED_TYPE_GENERIC, CRED_PERSIST_LOCAL_MACHINE

    @staticmethod
    def _win_target(name: str) -> str:
        return f"{SERVICE}:{name}"

    def _win_set(self, name: str, secret: str) -> None:
        advapi, Credential, cred_type, persist = self._win_api()
        blob = secret.encode("utf-8")
        buf = (ctypes.c_ubyte * len(blob)).from_buffer_copy(blob)
        cred = Credential()
        cred.Type = cred_type
        cred.TargetName = self._win_target(name)
        cred.CredentialBlobSize = len(blob)
        cred.CredentialBlob = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))
        cred.Persist = persist
        cred.UserName = SERVICE
        if not advapi.CredWriteW(ctypes.byref(cred), 0):
            raise CredentialStoreError(f"Windows Credential Manager write failed: {ctypes.get_last_error()}")

    def _win_get(self, name: str) -> str:
        advapi, Credential, cred_type, _ = self._win_api()
        ptr = ctypes.POINTER(Credential)()
        if not advapi.CredReadW(self._win_target(name), cred_type, 0, ctypes.byref(ptr)):
            raise CredentialStoreError("credential not found in Windows Credential Manager")
        try:
            cred = ptr.contents
            data = ctypes.string_at(cred.CredentialBlob, cred.CredentialBlobSize)
            return data.decode("utf-8")
        finally:
            advapi.CredFree(ptr)

    def _win_delete(self, name: str) -> bool:
        advapi, _, cred_type, _ = self._win_api()
        if advapi.CredDeleteW(self._win_target(name), cred_type, 0):
            return True
        error = ctypes.get_last_error()
        if error == 1168:  # ERROR_NOT_FOUND
            return False
        raise CredentialStoreError(f"Windows Credential Manager delete failed: {error}")
