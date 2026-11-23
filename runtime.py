"""Per-user session process. Browser unlock and private Unix-socket credential IPC."""

from datetime import datetime, timezone
import fcntl
import http.server
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import socketserver
import struct
import subprocess
import threading
import time

from fido2.server import Fido2Server
from fido2.webauthn import AttestedCredentialData, PublicKeyCredentialUserEntity

from probe import Handler, ProbeError, WEB, decode, encode
from vault_core import MAX_CONFIG, Store, VaultError, cluster_binding, managed_projection, parse, prepare, private_directory, write_private

MAX_IPC = 24 * 1024 * 1024


def session_clock():
    # Linux CLOCK_BOOTTIME includes laptop suspend time.
    return time.clock_gettime(time.CLOCK_BOOTTIME)


class Runtime:
    def __init__(self, state, ttl=3600, browser=True, runtime_dir=None):
        self.store = Store(state)
        self.ttl = ttl
        self.browser = browser
        # Linux's user runtime directory is normally tmpfs. Tests override it.
        root = Path(runtime_dir) if runtime_dir else Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}"))
        if not root.is_dir() or root.stat().st_uid != os.getuid():
            raise VaultError("A private XDG_RUNTIME_DIR is required for temporary editing.")
        self.scratch = private_directory(root / ("kube-unlock-" + hashlib.sha256(str(self.store.path).encode()).hexdigest()[:16]))
        self.condition = threading.Condition(threading.RLock())
        self.key = None
        self.payload = None
        self.deadline = 0
        self.expires = 0
        self.job = None
        self.cooldown = 0
        self.last_error = "Unlock cancelled or timed out."
        self.staging = None
        self.stopping = threading.Event()
        self.server = VaultHTTP(self)
        self.fido = Fido2Server({"id": "localhost", "name": "Kube unlock"}, verify_origin=lambda value: value == self.server.origin)
        self.fido.timeout = 120000

    def clear(self):
        if self.key is not None:
            self.key[:] = bytes(len(self.key))
        self.key = None
        self.payload = None
        self.deadline = self.expires = 0

    def expire(self):
        with self.condition:
            if self.key is not None and (session_clock() >= self.deadline or time.time() >= self.expires):
                self.clear()
            if self.job and session_clock() >= self.job["deadline"]:
                self.fail("Unlock timed out. Run unlock to retry.")

    def fail(self, message):
        self.job = None
        self.last_error = message
        self.cooldown = session_clock() + 30
        self.condition.notify_all()

    def current(self):
        current = self.store.current()
        if not current:
            raise VaultError("No vault exists. Run import with an explicit source file.")
        return current

    def launch(self, mode):
        if self.job:
            return
        self.job = {"id": secrets.token_urlsafe(32), "mode": mode, "deadline": session_clock() + 300, "pending": None}
        if mode == "enroll":
            self.job["candidate"] = {"prfSalt": encode(secrets.token_bytes(32)), "kdfSalt": encode(secrets.token_bytes(32))}
        if self.browser:
            try:
                opener = subprocess.Popen(["xdg-open", self.url()], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
                job = self.job
                def monitor():
                    try:
                        failed = opener.wait(timeout=10) != 0
                    except subprocess.TimeoutExpired:
                        return
                    if failed:
                        with self.condition:
                            if self.job is job:
                                self.fail("The default browser did not open. Check xdg-open and retry unlock.")
                threading.Thread(target=monitor, daemon=True).start()
            except OSError:
                self.fail("Unable to open a browser. Check xdg-open and retry unlock.")

    def url(self):
        return self.server.origin + "/#" + self.job["id"] if self.job else None

    def wait_key(self, fresh=False):
        with self.condition:
            self.expire()
            if fresh:
                if self.job:
                    raise VaultError("Another unlock is already in progress.")
                self.clear()
                self.cooldown = 0
            if self.key is not None:
                return
            if session_clock() < self.cooldown:
                raise VaultError(self.last_error)
            self.current()
            self.launch("unlock")
            while self.job and self.key is None:
                self.condition.wait(timeout=1)
                self.expire()
            if self.key is None:
                raise VaultError(self.last_error)

    def verify_client(self, response):
        client = json.loads(decode(response["response"]["clientDataJSON"]))
        if client.get("crossOrigin", False) is not False or "topOrigin" in client:
            raise VaultError("Cross-origin authentication is not allowed.")

    def web(self, operation, body):
        with self.condition:
            self.expire()
            job = self.job
            if not job:
                raise VaultError("No pending unlock. Run the command again.")
            if operation == "status":
                recipients = self.current()[1]["recipients"] if job["mode"] == "unlock" else []
                return {"mode": job["mode"], "registered": "credential" in job.get("candidate", {}),
                        "keys": [{"index": i, "name": f"Security key {i + 1}"} for i in range(len(recipients))]}
            if operation == "cancel":
                self.fail("Unlock cancelled. Run unlock to retry.")
                return {"ok": True}
            if operation == "begin":
                registering = job["mode"] == "enroll" and "credential" not in job["candidate"]
                if registering:
                    existing = self.store.current()
                    excluded = [AttestedCredentialData(decode(r["credential"])) for r in existing[1]["recipients"]] if existing else []
                    options, state = self.fido.register_begin(
                        PublicKeyCredentialUserEntity(id=secrets.token_bytes(32), name="kube-unlock", display_name="Local kubeconfig vault"),
                        credentials=excluded, authenticator_attachment="cross-platform", resident_key_requirement="discouraged",
                        user_verification="required", extensions={"prf": {}},
                    )
                    recipient = job["candidate"]
                else:
                    if job["mode"] == "enroll":
                        recipient = job["candidate"]
                    else:
                        recipients = self.current()[1]["recipients"]
                        index = body.get("key", 0)
                        if type(index) is not int or not 0 <= index < len(recipients):
                            raise VaultError("Unknown security key.")
                        recipient = recipients[index]
                    credential = AttestedCredentialData(decode(recipient["credential"]))
                    options, state = self.fido.authenticate_begin([credential], user_verification="required", extensions={"prf": {"eval": {"first": recipient["prfSalt"]}}})
                request = secrets.token_urlsafe(24)
                job["pending"] = (request, state, recipient, registering, session_clock())
                result = {"request": request, "options": dict(options), "registering": registering, "mode": job["mode"]}
                if registering:
                    result["options"]["publicKey"]["hints"] = ["security-key"]
                else:
                    result["options"]["publicKey"]["allowCredentials"][0]["transports"] = ["usb"]
                    result["kdfSalt"] = recipient["kdfSalt"]
                    if job["mode"] == "unlock":
                        result["envelope"] = recipient["envelope"]
                    elif self.key is not None:
                        result["dataKey"] = encode(self.key)
                return result
            if operation != "finish" or not job.get("pending"):
                raise VaultError("No pending authentication step.")
            request, state, recipient, registering, started = job["pending"]
            job["pending"] = None
            if not secrets.compare_digest(request, str(body.get("request", ""))) or session_clock() - started > 120:
                raise VaultError("Authentication step expired or mismatched.")
            response = body["credential"]
            self.verify_client(response)
            if registering:
                if response.get("authenticatorAttachment") != "cross-platform" or body.get("prfEnabled") is not True:
                    raise VaultError("Choose a USB security key with PRF support.")
                auth = self.fido.register_complete(state, response)
                recipient["credential"] = encode(auth.credential_data)
                return {"registered": True}
            self.fido.authenticate_complete(state, [AttestedCredentialData(decode(recipient["credential"]))], response)
            key = decode(body["dataKey"])
            if len(key) != 32:
                raise VaultError("Invalid encryption key.")
            if job["mode"] == "enroll":
                envelope = body["envelope"]
                if len(decode(envelope["iv"])) != 12 or len(decode(envelope["ciphertext"])) != 48:
                    raise VaultError("Invalid key envelope.")
                recipient["envelope"] = {"iv": envelope["iv"], "ciphertext": envelope["ciphertext"]}
                current = self.store.current()
                if current:
                    if self.key is None or not secrets.compare_digest(self.key, key):
                        raise VaultError("The active vault key changed. Retry key enrollment.")
                    self.store.commit(self.payload, key, [*current[1]["recipients"], recipient], current[0])
                else:
                    if self.staging is None:
                        raise VaultError("No import is waiting.")
                    self.store.commit(self.staging, key, [recipient])
                    self.payload = self.staging
                    self.staging = None
            else:
                self.payload = self.store.decrypt(self.current()[1], key)
            self.key = bytearray(key)
            self.deadline = session_clock() + self.ttl
            self.expires = time.time() + self.ttl
            self.job = None
            self.cooldown = 0
            self.condition.notify_all()
            return {"unlocked": True}

    def check_generated(self):
        observed = parse((self.store.path / "current" / "kubeconfig").read_text())
        if managed_projection(observed) != managed_projection(self.payload["generated"]):
            raise VaultError("The generated connection file was edited. Restore it from the encrypted source using config repair, then edit through config unlock.")
        return observed

    def request(self, body):
        op = body.get("operation")
        with self.condition:
            self.expire()
            if op == "status":
                current = self.store.current()
                return {"initialized": bool(current), "unlocked": self.key is not None, "expires": self.expires,
                        "editing": (self.scratch / "edit" / "kubeconfig").exists(), "waiting": bool(self.job),
                        "edit_path": str(self.scratch / "edit" / "kubeconfig") if (self.scratch / "edit" / "kubeconfig").exists() else None,
                        "keys": len(current[1]["recipients"]) if current else 0,
                        "session_seconds": self.ttl}
            if op == "backups":
                return {"generations": sorted(p.name for p in self.store.generations.iterdir() if p.is_dir() and not p.is_symlink() and (p / "vault.json").is_file())}
            if op in ("lock", "stop"):
                self.clear()
                if self.job:
                    self.fail("Locked by user.")
                if op == "stop":
                    self.stopping.set()
                return {"locked": True, "editing": (self.scratch / "edit" / "kubeconfig").exists()}
            if op == "config-discard":
                edit = self.scratch / "edit"
                if edit.exists():
                    (edit / "kubeconfig").unlink(missing_ok=True)
                    (edit / "generation").unlink(missing_ok=True)
                    edit.rmdir()
                self.clear()
                return {"discarded": True}
            if op == "import":
                if self.store.current() or self.staging or self.job:
                    raise VaultError("A vault or import already exists. It was not overwritten.")
                self.staging = prepare(body["text"], body["base"], self.store.path, token_files=body.get("token_files", False))
                self.launch("enroll")
                while self.job:
                    self.condition.wait(timeout=1)
                    self.expire()
                if not self.store.current():
                    self.staging = None
                    raise VaultError(self.last_error)
                return {"config": str(self.store.path / "current" / "kubeconfig"), "keys": 1}
        self.wait_key(fresh=op in ("unlock", "key-add"))
        with self.condition:
            self.expire()
            if self.key is None:
                raise VaultError("Session expired. Retry the command.")
            if op == "unlock":
                return {"unlocked": True, "expires": self.expires}
            if op == "credential":
                self.check_generated()
                cluster = body.get("cluster")
                if not isinstance(cluster, dict):
                    raise VaultError("Expected cluster details from the Kubernetes exec protocol.")
                for record in self.payload["records"].values():
                    if record["id"] == body.get("identity") and cluster_binding(cluster) in record["clusters"]:
                        expiry = self.expires
                        parts = record["token"].split(".")
                        if len(parts) == 3:
                            try:
                                exp = json.loads(decode(parts[1])).get("exp")
                                if type(exp) in (int, float):
                                    expiry = min(expiry, exp)
                            except (ValueError, TypeError, AttributeError):
                                pass
                        if expiry <= time.time():
                            raise VaultError("The existing Kubernetes token has expired.")
                        return {"apiVersion": "client.authentication.k8s.io/v1", "kind": "ExecCredential", "status": {
                            "token": record["token"], "expirationTimestamp": datetime.fromtimestamp(expiry, timezone.utc).isoformat().replace("+00:00", "Z"),
                        }}
                raise VaultError("Credential or destination does not match the enrolled configuration.")
            if op == "key-add":
                self.launch("enroll")
                while self.job:
                    self.condition.wait(timeout=1)
                    self.expire()
                if self.key is None or self.cooldown:
                    raise VaultError(self.last_error)
                return {"keys": len(self.current()[1]["recipients"])}
            edit = self.scratch / "edit"
            if op == "config-unlock":
                if edit.exists():
                    raise VaultError("An edit session already exists. Save or explicitly discard it first.")
                self.check_generated()
                private_directory(edit)
                write_private(edit / "generation", self.current()[0].encode())
                write_private(edit / "kubeconfig", self.payload["text"].encode())
                return {"path": str(edit / "kubeconfig")}
            if op == "config-lock":
                if not edit.exists():
                    raise VaultError("No editable copy exists.")
                expected = (edit / "generation").read_text()
                observed = self.check_generated()
                new = prepare((edit / "kubeconfig").read_text(), self.payload["base"], self.store.path,
                              self.payload, self.payload.get("token_files", False))
                if new["generated"]["clusters"] != self.payload["generated"]["clusters"] and not body.get("accept_connections"):
                    raise VaultError("Cluster connection/trust settings changed. Review your edits, then repeat config lock --accept-connection-changes.")
                old_source = parse(self.payload["text"])
                new_source = parse(new["text"])
                if old_source.get("current-context") == new_source.get("current-context"):
                    selected = observed.get("current-context", "")
                    if not selected or selected in {c["name"] for c in new["generated"]["contexts"]}:
                        new["generated"]["current-context"] = selected
                old_contexts = {c["name"]: c["context"] for c in old_source.get("contexts", [])}
                observed_contexts = {c["name"]: c["context"] for c in observed.get("contexts", [])}
                for context in new["generated"]["contexts"]:
                    name = context["name"]
                    if name in old_contexts and context["context"].get("namespace") == old_contexts[name].get("namespace"):
                        value = observed_contexts.get(name, {}).get("namespace")
                        if value is not None:
                            context["context"]["namespace"] = value
                        elif name in observed_contexts:
                            context["context"].pop("namespace", None)
                self.store.commit(new, bytes(self.key), self.current()[1]["recipients"], expected)
                self.clear()
                (edit / "kubeconfig").unlink()
                (edit / "generation").unlink()
                edit.rmdir()
                return {"saved": True, "locked": True}
            if op == "config-repair":
                current = self.current()
                self.store.commit(self.payload, bytes(self.key), current[1]["recipients"], current[0])
                return {"repaired": True}
            if op == "export":
                return {"text": self.payload["text"]}
            if op == "restore":
                if edit.exists():
                    raise VaultError("Save or discard the existing edit session before restoring a backup.")
                generation = body.get("generation", "")
                if len(generation) != 32 or any(c not in "0123456789abcdef" for c in generation):
                    raise VaultError("Invalid backup generation.")
                document = json.loads((self.store.generations / generation / "vault.json").read_text())
                payload = self.store.decrypt(document, bytes(self.key))
                self.store.commit(payload, bytes(self.key), self.current()[1]["recipients"], self.current()[0])
                self.clear()
                return {"restored": True}
            raise VaultError("Unknown operation.")


class VaultHTTP(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, runtime):
        self.runtime = runtime
        super().__init__(("127.0.0.1", 0), VaultHandler)
        self.origin = f"http://localhost:{self.server_port}"

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(5)
        return connection, address

    def handle_error(self, request, address):
        pass


class VaultHandler(Handler):
    def do_GET(self):
        try:
            self.gate()
            assets = {"/": ("vault.html", "text/html; charset=utf-8"), "/vault.js": ("vault.js", "text/javascript"),
                      "/crypto.mjs": ("crypto.mjs", "text/javascript"), "/style.css": ("style.css", "text/css")}
            if self.path not in assets:
                self.reply(404, {"error": "Not found."})
                return
            file, mime = assets[self.path]
            self.reply(200, (WEB / file).read_bytes(), mime)
        except ProbeError:
            self.reply(403, {"error": "Invalid local request."})

    def do_POST(self):
        try:
            self.gate(post=True)
            runtime = self.server.runtime
            with runtime.condition:
                runtime.expire()
                if not runtime.job or self.headers.get_all("X-Unlock-Request") != [runtime.job["id"]]:
                    raise VaultError("This unlock link is invalid or expired. Run the command again.")
                lengths = self.headers.get_all("Content-Length") or []
                if self.headers.get_all("Content-Type") != ["application/json"] or self.headers.get("Transfer-Encoding") or len(lengths) != 1 or not lengths[0].isdigit() or not 0 < int(lengths[0]) <= 32768:
                    raise VaultError("Expected a bounded JSON request.")
                body = json.loads(self.rfile.read(int(lengths[0])))
                if not isinstance(body, dict) or not self.path.startswith("/api/"):
                    raise VaultError("Invalid request.")
                result = runtime.web(self.path.removeprefix("/api/"), body)
            self.reply(200, result)
        except (VaultError, ProbeError) as exc:
            self.reply(400, {"error": str(exc)})
        except Exception:
            self.reply(400, {"error": "Authentication failed. Retry the step or cancel."})


class IPCHandler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            self.connection.settimeout(310)
            _, uid, _ = struct.unpack("3i", self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != os.getuid():
                return
            line = self.rfile.readline(MAX_IPC + 1)
            if len(line) > MAX_IPC or not line.endswith(b"\n"):
                raise VaultError("IPC request is too large or incomplete.")
            request = json.loads(line)
            if not isinstance(request, dict):
                raise VaultError("Invalid request.")
            result = {"result": self.server.runtime.request(request)}
        except (VaultError, ProbeError) as exc:
            result = {"error": str(exc)}
        except Exception:
            result = {"error": "Local operation failed. No credential details are logged."}
        try:
            self.wfile.write(json.dumps(result).encode() + b"\n")
        except OSError:
            pass


class IPCServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def handle_error(self, request, address):
        pass


def serve(state, ttl=3600, browser=True):
    state = private_directory(state)
    with open(state / "daemon.lock", "a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        sock = state / "session.sock"
        sock.unlink(missing_ok=True)
        runtime = Runtime(state, ttl, browser)
        with runtime.server, IPCServer(str(sock), IPCHandler) as ipc:
            os.chmod(sock, 0o600)
            ipc.runtime = runtime
            threading.Thread(target=runtime.server.serve_forever, daemon=True).start()
            threading.Thread(target=ipc.serve_forever, daemon=True).start()
            try:
                while not runtime.stopping.wait(1):
                    runtime.expire()
            except KeyboardInterrupt:
                pass
            finally:
                runtime.clear()
                runtime.server.shutdown()
                ipc.shutdown()
                sock.unlink(missing_ok=True)
