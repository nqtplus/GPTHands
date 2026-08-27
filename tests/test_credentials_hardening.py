from __future__ import annotations

import ctypes
import unittest
from unittest import mock

from gpthands import credentials
from gpthands.credentials import CredentialStore


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


if __name__ == "__main__":
    unittest.main()
