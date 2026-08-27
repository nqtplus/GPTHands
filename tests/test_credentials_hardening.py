from __future__ import annotations

import ctypes
import subprocess
import unittest
from unittest import mock

from gpthands import credentials
from gpthands.credentials import CredentialStore, CredentialStoreError


class _FakeSecurity:
    def __init__(self) -> None:
        self.added: bytes | None = None

    def SecKeychainAddGenericPassword(
        self,
        _keychain,
        _service_len,
        _service,
        _account_len,
        _account,
        password_len,
        password_data,
        _item,
    ) -> int:
        self.added = ctypes.string_at(password_data, password_len)
        return 0

    def SecKeychainItemModifyAttributesAndData(self, *_args) -> int:
        return 0


class _FakeCore:
    def CFRelease(self, _item) -> None:
        return None


class CredentialHardeningTests(unittest.TestCase):
    def test_macos_set_uses_native_buffer_not_subprocess_argv(self) -> None:
        secret = "SECRET_SHOULD_NEVER_BE_PROCESS_ARGV"
        security = _FakeSecurity()
        core = _FakeCore()
        not_found = (
            credentials._ERR_SEC_ITEM_NOT_FOUND,
            ctypes.c_void_p(),
            ctypes.c_uint32(),
            ctypes.c_void_p(),
            (security, core),
        )
        with mock.patch.object(CredentialStore, "_mac_find", return_value=not_found), mock.patch(
            "gpthands.credentials.subprocess.run"
        ) as run:
            CredentialStore._mac_set("demo", secret)
        run.assert_not_called()
        self.assertEqual(security.added, secret.encode("utf-8"))

    def test_darwin_backend_requires_native_security_framework(self) -> None:
        with mock.patch("gpthands.credentials.platform.system", return_value="Darwin"), mock.patch.object(
            CredentialStore, "_mac_api", return_value=(_FakeSecurity(), _FakeCore())
        ):
            self.assertEqual(CredentialStore().backend(), "macos-keychain")

    def test_portable_secret_size_limit_is_fail_closed_before_backend(self) -> None:
        too_large = "X" * (credentials._MAX_SECRET_BYTES + 1)
        with mock.patch.object(CredentialStore, "backend") as backend:
            with self.assertRaises(CredentialStoreError):
                CredentialStore().set("demo", too_large)
        backend.assert_not_called()

    def test_secret_service_helper_is_absolute_and_timeout_bounded(self) -> None:
        completed = subprocess.CompletedProcess(
            ["/usr/bin/secret-tool"],
            0,
            stdout="",
            stderr="",
        )
        with mock.patch.object(CredentialStore, "_linux_tool", return_value="/usr/bin/secret-tool"), mock.patch(
            "gpthands.credentials.subprocess.run", return_value=completed
        ) as run:
            CredentialStore._linux_set("demo", "secret")
        argv = run.call_args.args[0]
        self.assertEqual(argv[0], "/usr/bin/secret-tool")
        self.assertEqual(run.call_args.kwargs["timeout"], credentials._SECRET_TOOL_TIMEOUT_SECONDS)
        self.assertFalse(run.call_args.kwargs["shell"])

    def test_secret_service_timeout_becomes_credential_error(self) -> None:
        with mock.patch.object(CredentialStore, "_linux_tool", return_value="/usr/bin/secret-tool"), mock.patch(
            "gpthands.credentials.subprocess.run",
            side_effect=subprocess.TimeoutExpired(["/usr/bin/secret-tool"], 10),
        ):
            with self.assertRaisesRegex(CredentialStoreError, "timed out"):
                CredentialStore._linux_get("demo")


if __name__ == "__main__":
    unittest.main()
