"""Synthetic-only integration harness; never a production runtime entry point."""
import base64
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
import signal
import ssl
import sys
import threading
import time
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import yaml
from runtime import IPCHandler, IPCServer, Runtime
from vault_core import private_directory

root = Path(sys.argv[1])
state = private_directory(root / "state")
calls = []
token = "synthetic-integration-token-never-a-real-credential"


class API(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        path = urlsplit(self.path).path
        valid = self.headers.get("Authorization") == "Bearer " + token
        calls.append({"path": self.path, "authenticated": valid})
        code, body = 200, {"kind": "List", "apiVersion": "v1", "items": []}
        if not valid:
            code, body = 401, {"kind": "Status", "status": "Failure", "reason": "Unauthorized", "code": 401}
        elif path == "/version":
            body = {"major": "1", "minor": "32", "gitVersion": "v1.32.0", "platform": "linux/amd64"}
        elif path.startswith("/api/v1/namespaces"):
            body = {"kind": "NamespaceList", "apiVersion": "v1", "metadata": {"resourceVersion": "1"}, "items": []}
        elif path == "/api":
            body = {"kind": "APIVersions", "versions": ["v1"], "serverAddressByClientCIDRs": []}
        elif path == "/apis":
            body = {"kind": "APIGroupList", "apiVersion": "v1", "groups": []}
        elif path == "/api/v1":
            body = {"kind": "APIResourceList", "groupVersion": "v1", "resources": [{"name": name, "singularName": "", "namespaced": False, "kind": kind, "verbs": ["get", "list", "watch"]} for name, kind in [("namespaces", "Namespace"), ("nodes", "Node")]]}
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic local test")])
now = datetime.now(timezone.utc)
certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(private.public_key())
               .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
               .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
               .add_extension(x509.BasicConstraints(ca=True, path_length=None), True).sign(private, hashes.SHA256()))
cert = certificate.public_bytes(serialization.Encoding.PEM)
(root / "test-ca.pem").write_bytes(cert)
(root / "test-server-key.pem").write_bytes(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
api = ThreadingHTTPServer(("127.0.0.1", 0), API)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(root / "test-ca.pem", root / "test-server-key.pem")
api.socket = context.wrap_socket(api.socket, server_side=True)
threading.Thread(target=api.serve_forever, daemon=True).start()
source = {"apiVersion": "v1", "kind": "Config", "clusters": [{"name": "synthetic", "cluster": {
    "server": f"https://127.0.0.1:{api.server_port}", "certificate-authority-data": base64.b64encode(cert).decode()}}],
    "users": [{"name": "synthetic", "user": {"token": token}}],
    "contexts": [{"name": "synthetic", "context": {"cluster": "synthetic", "user": "synthetic"}}], "current-context": "synthetic"}
(root / "source.yaml").write_text("# Synthetic integration fixture.\n" + yaml.safe_dump(source))


def start():
    runtime = Runtime(state, browser=False, runtime_dir=root)
    sock = state / "session.sock"
    sock.unlink(missing_ok=True)
    ipc = IPCServer(str(sock), IPCHandler)
    ipc.runtime = runtime
    threading.Thread(target=runtime.server.serve_forever, daemon=True).start()
    threading.Thread(target=ipc.serve_forever, daemon=True).start()
    return runtime, ipc


def stop(runtime, ipc):
    runtime.clear()
    runtime.server.shutdown()
    runtime.server.server_close()
    ipc.shutdown()
    ipc.server_close()


runtime, ipc = start()
print(json.dumps({"ready": True, "state": str(state), "source": str(root / "source.yaml")}), flush=True)
try:
    for line in sys.stdin:
        command = json.loads(line)["command"]
        if command == "job":
            with runtime.condition:
                result = {"url": runtime.url(), "mode": runtime.job["mode"] if runtime.job else None}
        elif command == "expire":
            runtime.deadline = time.monotonic() - 1
            runtime.expire()
            result = {"expired": True}
        elif command == "restart":
            stop(runtime, ipc)
            runtime, ipc = start()
            result = {"restarted": True}
        elif command == "calls":
            result = {"calls": calls}
        elif command == "stop":
            print(json.dumps({"stopped": True}), flush=True)
            break
        else:
            result = {"error": "Unknown test command"}
        print(json.dumps(result), flush=True)
finally:
    stop(runtime, ipc)
    api.shutdown()
    api.server_close()
