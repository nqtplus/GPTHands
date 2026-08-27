from __future__ import annotations

import io
import json
import unittest

from gpthands.stable_server import serve_stdio_bounded


class _FakeServer:
    def handle(self, message):
        return {"jsonrpc": "2.0", "id": message.get("id"), "result": {"ok": True}}


class StableStdioTests(unittest.TestCase):
    def test_oversized_line_is_discarded_and_next_request_survives(self) -> None:
        valid = json.dumps({"jsonrpc": "2.0", "id": 7, "method": "ping"}).encode("utf-8") + b"\n"
        source = io.BytesIO(b"X" * 1500 + b"\n" + valid)
        sink = io.StringIO()
        result = serve_stdio_bounded(
            _FakeServer(),
            max_request_bytes=1024,
            input_buffer=source,
            output=sink,
        )
        self.assertEqual(result, 0)
        rows = [json.loads(line) for line in sink.getvalue().splitlines()]
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["error"]["code"], -32700)
        self.assertIn("input byte limit", rows[0]["error"]["message"])
        self.assertEqual(rows[1]["id"], 7)
        self.assertTrue(rows[1]["result"]["ok"])


if __name__ == "__main__":
    unittest.main()
