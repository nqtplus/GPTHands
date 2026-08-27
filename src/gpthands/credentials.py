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
_ERR_SEC_ITEM_NOT_FOUND = -25300
_MAX_SECRET_BYTES = 2560
_SECRET_TOOL_TIMEOUT_SECONDS = 10


def _name(value: str) -> str:
    value = value.strip()
    if not value or len(value) > 128 or any(ch in value for ch in "\r\n\x00"):
        raise CredentialStoreError("credential name is invalid")
    return value


def _secret_bytes(secret: str) -> bytes:
    if not isinstance(secret, str) or not secret or "\x00" in secret:
        raise CredentialStoreError("credential value is invalid")
    encoded = secret.encode("utf-8")
    if len(encoded) > _MAX_SECRET_BYTES:
        raise CredentialStoreError(f"credential exceeds {_MAX_SECRET_BYTES}-byte portable limit")
    return encoded


class CredentialStore:
    """OS-backed secret storage. There is intentionally no plaintext fallback."""

    @staticmethod
    def _linux_tool() -> str:
        candidate = shutil.which("secret-tool")
        if not candidate:
            raise CredentialStoreError("Secret Service helper `secret-tool` is unavailable")
        try:
            path = Path(candidate).expanduser().resolve(strict=True)
        except OSError as exc:
            raise CredentialStoreError("Secret Service helper cannot be resolved safely") from exc
        if not path.is_file():
            raise CredentialStoreError("Secret Service helper is not a regular file")
        return str(path)

    def backend(self) -> str:
        system = platform.system()
        if system == "Darwin":
            try:
                self._mac_api()
            except (OSError, AttributeError) as exc:
                raise CredentialStoreError("macOS Security.framework Keychain API is unavailable") from exc
            return "macos-keychain"
        if system == "Windows":
            return "windows-credential-manager"
        if system == "Linux":
            self._linux_tool()
            return "linux-secret-service"
        raise CredentialStoreError("no supported OS credential store is available")

    def set(self, name: str, secret: str) -> None:
        name = _name(name)
        _secret_bytes(secret)
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
    def _mac_api():
        security = ctypes.CDLL(
            "/System/Library/Frameworks/Security.framework/Security",
            use_errno=True,
        )
        core = ctypes.CDLL(
            "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
            use_errno=True,
        )

        security.SecKeychainFindGenericPassword.restype = ctypes.c_int32
        security.SecKeychainFindGenericPassword.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_char_p,
            ctypes.c_uint32,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
        ]
        security.SecKeychainAddGenericPassword.restype = ctypes.c_int32
        security.SecKeychainAddGenericPassword.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_char_p,
            ctypes.c_uint32,
            ctypes.c_char_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        security.SecKeychainItemModifyAttributesAndData.restype = ctypes.c_int32
        security.SecKeychainItemModifyAttributesAndData.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        security.SecKeychainItemDelete.restype = ctypes.c_int32
        security.SecKeychainItemDelete.argtypes = [ctypes.c_void_p]
        security.SecKeychainItemFreeContent.restype = ctypes.c_int32
        security.SecKeychainItemFreeContent.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        core.CFRelease.restype = None
        core.CFRelease.argtypes = [ctypes.c_void_p]
        return security, core

    @staticmethod
    def _mac_strings(name: str) -> tuple[bytes, bytes]:
        return SERVICE.encode("utf-8"), name.encode("utf-8")

    @classmethod
    def _mac_find(
        cls,
        name: str,
        *,
        include_password: bool,
    ) -> tuple[int, object, object, object, object]:
        security, core = cls._mac_api()
        service, account = cls._mac_strings(name)
        item = ctypes.c_void_p()
        password_length = ctypes.c_uint32()
        password_data = ctypes.c_void_p()
        status = security.SecKeychainFindGenericPassword(
            None,
            len(service),
            service,
            len(account),
            account,
            ctypes.byref(password_length) if include_password else None,
            ctypes.byref(password_data) if include_password else None,
            ctypes.byref(item),
        )
        return int(status), item, password_length, password_data, (security, core)

    @classmethod
    def _mac_set(cls, name: str, secret: str) -> None:
        # Do not invoke `/usr/bin/security -w <secret>`: that would expose the
        # secret in process argv. Keep password bytes inside this process and
        # pass them directly to Security.framework.
        secret_bytes = _secret_bytes(secret)
        secret_buffer = ctypes.create_string_buffer(secret_bytes)
        status, item, _length, _data, apis = cls._mac_find(name, include_password=False)
        security, core = apis
        try:
            if status == 0 and item.value:
                modified = security.SecKeychainItemModifyAttributesAndData(
                    item,
                    None,
                    len(secret_bytes),
                    ctypes.cast(secret_buffer, ctypes.c_void_p),
                )
                if modified != 0:
                    raise CredentialStoreError(f"Keychain update failed with OSStatus {int(modified)}")
                return
            if status != _ERR_SEC_ITEM_NOT_FOUND:
                raise CredentialStoreError(f"Keychain lookup failed with OSStatus {status}")

            service, account = cls._mac_strings(name)
            added_item = ctypes.c_void_p()
            added = security.SecKeychainAddGenericPassword(
                None,
                len(service),
                service,
                len(account),
                account,
                len(secret_bytes),
                ctypes.cast(secret_buffer, ctypes.c_void_p),
                ctypes.byref(added_item),
            )
            if added != 0:
                raise CredentialStoreError(f"Keychain write failed with OSStatus {int(added)}")
            if added_item.value:
                core.CFRelease(added_item)
        finally:
            if item.value:
                core.CFRelease(item)
            # Best-effort overwrite of our mutable local copy. Python/ctypes
            # cannot guarantee erasure of every temporary immutable byte copy.
            ctypes.memset(secret_buffer, 0, len(secret_buffer))

    @classmethod
    def _mac_get(cls, name: str) -> str:
        status, item, password_length, password_data, apis = cls._mac_find(
            name,
            include_password=True,
        )
        security, core = apis
        try:
            if status == _ERR_SEC_ITEM_NOT_FOUND:
                raise CredentialStoreError("credential not found in Keychain")
            if status != 0:
                raise CredentialStoreError(f"Keychain read failed with OSStatus {status}")
            if password_length.value > _MAX_SECRET_BYTES:
                raise CredentialStoreError("Keychain credential exceeds portable size limit")
            if password_length.value and not password_data.value:
                raise CredentialStoreError("Keychain returned an invalid password buffer")
            raw = ctypes.string_at(password_data, password_length.value) if password_length.value else b""
            try:
                value = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise CredentialStoreError("Keychain credential is not valid UTF-8") from exc
            _secret_bytes(value)
            return value
        finally:
            if password_data.value:
                security.SecKeychainItemFreeContent(None, password_data)
            if item.value:
                core.CFRelease(item)

    @classmethod
    def _mac_delete(cls, name: str) -> bool:
        status, item, _length, _data, apis = cls._mac_find(name, include_password=False)
        security, core = apis
        try:
            if status == _ERR_SEC_ITEM_NOT_FOUND:
                return False
            if status != 0 or not item.value:
                raise CredentialStoreError(f"Keychain lookup failed with OSStatus {status}")
            deleted = security.SecKeychainItemDelete(item)
            if deleted != 0:
                raise CredentialStoreError(f"Keychain delete failed with OSStatus {int(deleted)}")
            return True
        finally:
            if item.value:
                core.CFRelease(item)

    @staticmethod
    def _linux_set(name: str, secret: str) -> None:
        tool = CredentialStore._linux_tool()
        try:
            proc = subprocess.run(
                [tool, "store", "--label", f"GPTHands {name}", "service", SERVICE, "name", name],
                input=secret,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
                timeout=_SECRET_TOOL_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            raise CredentialStoreError("Secret Service write timed out") from exc
        if proc.returncode != 0:
            raise CredentialStoreError(f"Secret Service write failed: {proc.stderr.strip()[:300]}")

    @staticmethod
    def _linux_get(name: str) -> str:
        tool = CredentialStore._linux_tool()
        try:
            proc = subprocess.run(
                [tool, "lookup", "service", SERVICE, "name", name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
                timeout=_SECRET_TOOL_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            raise CredentialStoreError("Secret Service read timed out") from exc
        value = proc.stdout.rstrip("\r\n")
        if proc.returncode != 0 or not value:
            raise CredentialStoreError("credential not found in Secret Service")
        _secret_bytes(value)
        return value

    @staticmethod
    def _linux_delete(name: str) -> bool:
        tool = CredentialStore._linux_tool()
        try:
            proc = subprocess.run(
                [tool, "clear", "service", SERVICE, "name", name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                timeout=_SECRET_TOOL_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            raise CredentialStoreError("Secret Service delete timed out") from exc
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
        blob = _secret_bytes(secret)
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
            if cred.CredentialBlobSize > _MAX_SECRET_BYTES:
                raise CredentialStoreError("Windows credential exceeds portable size limit")
            data = ctypes.string_at(cred.CredentialBlob, cred.CredentialBlobSize)
            try:
                value = data.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise CredentialStoreError("Windows credential is not valid UTF-8") from exc
            _secret_bytes(value)
            return value
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
