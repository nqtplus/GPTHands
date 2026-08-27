from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from gpthands.policy import Policy, PolicyError
from gpthands.safe_write import stable_atomic_write


@unittest.skipIf(os.name == "nt", "POSIX dirfd race tests")
class StableAtomicWriteRaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name).resolve()
        self.workspace = self.base / "workspace"
        self.workspace.mkdir()
        self.parent = self.workspace / "safe"
        self.parent.mkdir()
        self.outside = self.base / "outside"
        self.outside.mkdir()
        self.policy = Policy(
            workspace=self.workspace,
            policy_path=self.base / "policy.json",
            max_write_bytes=4096,
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _swap_parent_to_outside_symlink(self) -> Path:
        moved = self.workspace / "safe-moved"
        self.parent.rename(moved)
        self.parent.symlink_to(self.outside, target_is_directory=True)
        return moved

    def test_no_overwrite_commit_is_anchored_to_open_directory(self) -> None:
        target = self.policy.resolve_path("safe/created.txt", must_exist=False)
        real_link = os.link
        moved_holder: list[Path] = []

        def swapping_link(src, dst, **kwargs):
            moved_holder.append(self._swap_parent_to_outside_symlink())
            return real_link(src, dst, **kwargs)

        with mock.patch("gpthands.safe_write.os.link", side_effect=swapping_link):
            stable_atomic_write(self.policy, target, "payload", overwrite=False)

        self.assertEqual((moved_holder[0] / "created.txt").read_text(), "payload")
        self.assertFalse((self.outside / "created.txt").exists())

    def test_overwrite_commit_is_anchored_to_open_directory(self) -> None:
        original = self.parent / "victim.txt"
        original.write_text("old", encoding="utf-8")
        (self.outside / "victim.txt").write_text("outside", encoding="utf-8")
        target = self.policy.resolve_path("safe/victim.txt", must_exist=True)
        real_replace = os.replace
        moved_holder: list[Path] = []

        def swapping_replace(src, dst, **kwargs):
            moved_holder.append(self._swap_parent_to_outside_symlink())
            return real_replace(src, dst, **kwargs)

        with mock.patch("gpthands.safe_write.os.replace", side_effect=swapping_replace):
            stable_atomic_write(self.policy, target, "new", overwrite=True)

        self.assertEqual((moved_holder[0] / "victim.txt").read_text(), "new")
        self.assertEqual((self.outside / "victim.txt").read_text(), "outside")

    def test_no_overwrite_remains_no_clobber_under_target_race(self) -> None:
        target = self.policy.resolve_path("safe/created.txt", must_exist=False)
        real_link = os.link

        def racing_link(src, dst, **kwargs):
            (self.parent / "created.txt").write_text("racer", encoding="utf-8")
            return real_link(src, dst, **kwargs)

        with mock.patch("gpthands.safe_write.os.link", side_effect=racing_link):
            with self.assertRaisesRegex(PolicyError, "created concurrently"):
                stable_atomic_write(self.policy, target, "payload", overwrite=False)

        self.assertEqual((self.parent / "created.txt").read_text(), "racer")


if __name__ == "__main__":
    unittest.main()
