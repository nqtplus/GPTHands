from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

import gpthands
from gpthands.stable_server import V10GPTHandsServer


class VersionConsistencyTests(unittest.TestCase):
    def test_public_versions_match_pyproject(self) -> None:
        root = Path(__file__).resolve().parents[1]
        version = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
        self.assertEqual(gpthands.__version__, version)
        self.assertEqual(V10GPTHandsServer.VERSION, version)


if __name__ == "__main__":
    unittest.main()
