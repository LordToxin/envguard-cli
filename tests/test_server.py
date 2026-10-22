"""Unit tests for the embedded server and REST endpoints."""

import unittest
import threading
import time
import urllib.request
import json
from envguard.server import run_server

class TestServerEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = 18787
        cls.server_thread = threading.Thread(
            target=run_server,
            kwargs={"host": "127.0.0.1", "port": cls.port},
            daemon=True,
        )
        cls.server_thread.start()
        time.sleep(0.5)

    def test_health_check(self):
        url = f"http://127.0.0.1:{self.port}/health"
        req = urllib.request.Request(url, headers={"Connection": "close"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode())
            self.assertEqual(data["status"], "ok")

    def test_api_audit_endpoint(self):
        url = f"http://127.0.0.1:{self.port}/api/audit"
        payload = json.dumps({"content": "PORT=3000\nAWS=" + "AKIA" + "IOSFODNN7EXAMPLE"}).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json", "Connection": "close"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode())
            self.assertEqual(data["status"], "failed")
            self.assertGreaterEqual(len(data["findings"]), 1)

    def test_api_template_endpoint(self):
        url = f"http://127.0.0.1:{self.port}/api/template"
        payload = json.dumps({"content": "PORT=5000\nOPENAI_API_KEY=sk-test"}).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json", "Connection": "close"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode())
            self.assertIn("PORT=", data["template"])
            self.assertIn("OPENAI_API_KEY=", data["template"])

if __name__ == "__main__":
    unittest.main()
