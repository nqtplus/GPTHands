from __future__ import annotations

import http.client
import tempfile
import threading
import unittest
from pathlib import Path

from gpthands.control_ui import create_control_server


class ControlUIHostHardeningTests(unittest.TestCase):
    def test_non_loopback_host_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp).resolve() / "workspace"
            workspace.mkdir()
            server = create_control_server(workspace, port=0)
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
            thread.start()
            try:
                port = server.server_address[1]
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                conn.request("GET", "/api/status", headers={"Host": "attacker.example"})
                response = conn.getresponse()
                body = response.read().decode("utf-8", errors="replace")
                conn.close()
                self.assertEqual(response.status, 400)
                self.assertIn("non-loopback Host", body)

                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                conn.request("GET", "/api/status", headers={"Host": f"127.0.0.1:{port}"})
                response = conn.getresponse()
                response.read()
                conn.close()
                self.assertEqual(response.status, 200)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
