import http.client
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest

from runtime import Runtime


class DaemonLifecycle(unittest.TestCase):
    def test_real_cli_autostart_and_stop(self):
        with tempfile.TemporaryDirectory(prefix="ku-lifecycle-") as directory:
            root = Path(directory)
            state = root / "state"
            command = ["/usr/bin/python3", str(Path(__file__).resolve().parents[1] / "kube_unlock.py"), "--state-dir", str(state)]
            environment = {**os.environ, "XDG_RUNTIME_DIR": directory}
            def run(*args):
                return subprocess.run([*command, *args], env=environment, capture_output=True, text=True, timeout=10, check=True)
            try:
                result = json.loads(run("status").stdout)
                self.assertFalse(result["initialized"])
                self.assertFalse(result["unlocked"])
                self.assertEqual(result["session_seconds"], 3600)
                self.assertEqual((state / "session.sock").stat().st_mode & 0o777, 0o600)
            finally:
                run("stop")
            for _ in range(30):
                if not (state / "session.sock").exists():
                    break
                time.sleep(0.1)
            self.assertFalse((state / "session.sock").exists())


class BrowserBoundary(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ku-http-")
        self.runtime = Runtime(Path(self.temp.name) / "state", browser=False, runtime_dir=self.temp.name)
        self.server = self.runtime.server
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        with self.runtime.condition:
            self.runtime.launch("enroll")
        self.capability = self.runtime.job["id"]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.runtime.clear()
        self.temp.cleanup()

    def post(self, operation, headers=None):
        client = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        request_headers = {"Host": self.server.origin.removeprefix("http://"), "Origin": self.server.origin,
                           "X-Unlock-Request": self.capability, "Content-Type": "application/json"}
        request_headers.update(headers or {})
        client.request("POST", "/api/" + operation, "{}", request_headers)
        response = client.getresponse()
        status, data = response.status, json.loads(response.read())
        client.close()
        return status, data

    def test_origin_host_and_launch_capability_are_required(self):
        for headers in [{"Host": "evil.invalid"}, {"Origin": "http://evil.invalid"},
                        {"X-Unlock-Request": "wrong"}, {"Sec-Fetch-Site": "cross-site"}]:
            self.assertEqual(self.post("status", headers)[0], 400)
        self.assertEqual(self.post("status")[0], 200)

    def test_cancel_invalidates_launch_capability(self):
        self.assertEqual(self.post("cancel")[0], 200)
        self.assertEqual(self.post("status")[0], 400)
        self.assertIsNone(self.runtime.job)

    def test_unknown_routes_never_return_credentials(self):
        for operation in ["token", "export", "source", "credential"]:
            self.assertEqual(self.post(operation)[0], 400)
