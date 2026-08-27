from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "release_bootstrap.py"
SPEC = importlib.util.spec_from_file_location("gpthands_release_bootstrap", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)


class ReleaseBootstrapSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name).resolve()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_wheel_digest_mismatch_is_refused(self) -> None:
        wheel = self.base / "artifact.whl"
        wheel.write_bytes(b"not-a-real-wheel-but-hash-check-runs-first")
        with self.assertRaisesRegex(bootstrap.BootstrapError, "SHA-256 mismatch"):
            bootstrap.verify_wheel_sha256(wheel, "0" * 64)

    def test_invalid_expected_digest_shape_is_refused(self) -> None:
        wheel = self.base / "artifact.whl"
        wheel.write_bytes(b"x")
        with self.assertRaisesRegex(bootstrap.BootstrapError, "64 hexadecimal"):
            bootstrap.verify_wheel_sha256(wheel, "not-a-digest")

    def test_symlink_wheel_is_refused(self) -> None:
        target = self.base / "real.whl"
        target.write_bytes(b"wheel")
        link = self.base / "linked.whl"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation unavailable on this platform")
        expected = bootstrap.sha256_file(target)
        with self.assertRaisesRegex(bootstrap.BootstrapError, "wheel must not be a symlink"):
            bootstrap.verify_wheel_sha256(link, expected)

    def test_release_marker_binds_version_to_one_wheel_digest(self) -> None:
        release = self.base / "release"
        release.mkdir()
        digest_a = "a" * 64
        digest_b = "b" * 64
        bootstrap._write_release_info(release, version="1.0.0rc1", wheel_sha256=digest_a)
        loaded = bootstrap._load_release_info(
            release, expected_version="1.0.0rc1", expected_sha256=digest_a
        )
        self.assertEqual(loaded["wheel_sha256"], digest_a)
        with self.assertRaisesRegex(bootstrap.BootstrapError, "different wheel digest"):
            bootstrap._load_release_info(
                release, expected_version="1.0.0rc1", expected_sha256=digest_b
            )

    def test_symlink_release_directory_is_refused(self) -> None:
        real = self.base / "real-release"
        real.mkdir()
        link = self.base / "release-link"
        try:
            link.symlink_to(real, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("directory symlink creation unavailable on this platform")
        with self.assertRaisesRegex(bootstrap.BootstrapError, "release directory must not be a symlink"):
            bootstrap._load_release_info(
                link, expected_version="1.0.0rc1", expected_sha256="a" * 64
            )

    def test_manifest_rejects_malformed_digest_binding(self) -> None:
        manifest = self.base / "install-state.json"
        manifest.write_text(
            json.dumps({
                "schema": 1,
                "current": "1.0.0rc1",
                "history": [],
                "digests": {"1.0.0rc1": "bad"},
            }),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(bootstrap.BootstrapError, "64 hexadecimal"):
            bootstrap._load_manifest(manifest)


if __name__ == "__main__":
    unittest.main()
