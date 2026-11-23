#!/usr/bin/env python3
"""Local, memory-only WebAuthn PRF compatibility probe. No credential-file I/O."""

import argparse
import base64
from dataclasses import dataclass, field
import hashlib
import http.cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import resource
import secrets
import threading
import time

from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialUserEntity

# The Ubuntu 24.04 package predates JSON mapping becoming the default in v2.
try:
    from fido2 import features

    features.webauthn_json_mapping.enabled = True
except (ImportError, AttributeError):
    pass

WEB = Path(__file__).resolve().parent / "web"
CHALLENGE_TTL = 120
SESSION_TTL = 900
MAX_BODY = 32768
MAX_SESSIONS = 8


class ProbeError(ValueError):
    """Safe, non-secret error suitable for the local UI."""


def encode(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def decode(value, maximum=8192):
    if not isinstance(value, str) or len(value) > maximum * 2:
        raise ProbeError("Invalid encoded response.")
    try:
        result = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, TypeError):
        raise ProbeError("Invalid encoded response.") from None
    if len(result) > maximum:
        raise ProbeError("Response is too large.")
    return result


@dataclass
class Session:
    csrf: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    created: float = field(default_factory=time.monotonic)
    stage: str = "new"
    pending: object = None
    credential: object = None
    prf_salt: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    kdf_salt: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    sample: bytes = field(default_factory=lambda: secrets.token_bytes(48))
    envelope: object = None
    lock: object = field(default_factory=threading.Lock)


class Probe:
    def __init__(self, origin):
        self.origin = origin
        self.fido = Fido2Server(
            {"id": "localhost", "name": "Kube unlock compatibility test"},
            verify_origin=lambda candidate: candidate == origin,
        )
        self.fido.timeout = CHALLENGE_TTL * 1000
        self.sessions = {}
        self.lock = threading.Lock()

    def get_session(self, cookie=None, create=False):
        now = time.monotonic()
        with self.lock:
            self.sessions = {k: s for k, s in self.sessions.items() if now - s.created < SESSION_TTL}
            if cookie in self.sessions:
                return cookie, self.sessions[cookie]
            if not create:
                raise ProbeError("Test session expired. Reload the page to start again.")
            if len(self.sessions) >= MAX_SESSIONS:
                raise ProbeError("Too many test sessions. Restart the probe.")
            identifier = secrets.token_urlsafe(32)
            session = Session()
            self.sessions[identifier] = session
            return identifier, session

    def begin(self, session, action):
        expected = {"register": "new", "seal": "registered", "open": "sealed"}
        if action not in expected or session.stage != expected[action]:
            raise ProbeError("This step is not available. Reload the page.")
        # A retry replaces the previous ceremony, making its response unusable.
        if action == "register":
            options, state = self.fido.register_begin(
                PublicKeyCredentialUserEntity(
                    id=secrets.token_bytes(32), name="compatibility-test", display_name="Temporary compatibility test"
                ),
                user_verification="required",
                authenticator_attachment="cross-platform",
                resident_key_requirement="discouraged",
                extensions={"prf": {}},
            )
        else:
            options, state = self.fido.authenticate_begin(
                [session.credential], user_verification="required",
                extensions={"prf": {"eval": {"first": encode(session.prf_salt)}}},
            )
        identifier = secrets.token_urlsafe(24)
        session.pending = (action, identifier, state, time.monotonic())
        result = {"request": identifier, "options": dict(options)}
        if action == "register":
            result["options"]["publicKey"]["hints"] = ["security-key"]
        else:
            result["options"]["publicKey"]["allowCredentials"][0]["transports"] = ["usb"]
            result["kdfSalt"] = encode(session.kdf_salt)
            if action == "seal":
                result["sample"] = encode(session.sample)
            else:
                result["envelope"] = session.envelope
        return result

    def finish(self, session, action, body):
        pending, session.pending = session.pending, None
        if pending is None:
            raise ProbeError("No pending request. Start this step again.")
        kind, identifier, state, started = pending
        if kind != action or not secrets.compare_digest(identifier, str(body.get("request", ""))):
            raise ProbeError("Request does not match the pending step.")
        if time.monotonic() - started > CHALLENGE_TTL:
            raise ProbeError("Request expired. Start this step again.")
        response = body.get("credential", {})
        try:
            client = json.loads(decode(response["response"]["clientDataJSON"]))
            if client.get("crossOrigin", False) is not False or "topOrigin" in client:
                raise ProbeError("Embedded or cross-origin authentication is not allowed.")
            if action == "register":
                if response.get("authenticatorAttachment") != "cross-platform":
                    raise ProbeError("Choose your physical USB security key.")
                if body.get("prfEnabled") is not True:
                    raise ProbeError("This browser/key did not enable PRF. Do not import any credentials.")
                auth = self.fido.register_complete(state, response)
                if decode(response["rawId"]) != auth.credential_data.credential_id:
                    raise ProbeError("Credential identifier mismatch.")
                session.credential = auth.credential_data
                session.stage = "registered"
            else:
                self.fido.authenticate_complete(state, [session.credential], response)
                if action == "seal":
                    envelope = body["envelope"]
                    if len(decode(envelope["iv"])) != 12 or len(decode(envelope["ciphertext"])) != len(session.sample) + 16:
                        raise ProbeError("Invalid encrypted sample.")
                    session.envelope = {"iv": envelope["iv"], "ciphertext": envelope["ciphertext"]}
                    session.stage = "sealed"
                elif action == "open":
                    if not secrets.compare_digest(decode(body["sample"]), session.sample):
                        raise ProbeError("The decrypted sample did not match.")
                    session.stage = "passed"
                else:
                    raise ProbeError("Unknown operation.")
        except ProbeError:
            raise
        except (ValueError, KeyError, TypeError, AttributeError):
            raise ProbeError("WebAuthn verification failed. Start this step again.") from None
        return {"stage": session.stage}


class ProbeServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port=0):
        super().__init__(("127.0.0.1", port), Handler)
        self.origin = f"http://localhost:{self.server_port}"
        self.probe = Probe(self.origin)

    def get_request(self):
        sock, address = super().get_request()
        sock.settimeout(5)
        return sock, address

    def handle_error(self, request, client_address):
        # Never dump request bodies or credential objects via exception logging.
        pass


class Handler(BaseHTTPRequestHandler):
    server_version = "KubeUnlockProbe"
    sys_version = ""

    def log_message(self, *args):
        pass

    def reply(self, status, data, content_type="application/json", cookie=None):
        if not isinstance(data, bytes):
            data = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        if cookie:
            self.send_header("Set-Cookie", f"kube_probe={cookie}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_TTL}")
        self.end_headers()
        self.wfile.write(data)

    def gate(self, post=False):
        if self.headers.get_all("Host") != [self.server.origin.removeprefix("http://")]:
            raise ProbeError("Unexpected Host header. Use the printed localhost address.")
        if self.headers.get("Sec-Fetch-Site") not in (None, "none", "same-origin"):
            raise ProbeError("Cross-origin requests are not allowed.")
        if post and self.headers.get_all("Origin") != [self.server.origin]:
            raise ProbeError("Unexpected request origin.")

    def session(self, create=False):
        cookies = http.cookies.SimpleCookie()
        try:
            cookies.load(self.headers.get("Cookie", ""))
        except http.cookies.CookieError:
            raise ProbeError("Invalid session cookie.") from None
        cookie = cookies.get("kube_probe")
        return self.server.probe.get_session(cookie.value if cookie else None, create)

    def do_GET(self):
        try:
            self.gate()
            if self.path == "/":
                identifier, _ = self.session(create=True)
                self.reply(200, (WEB / "index.html").read_bytes(), "text/html; charset=utf-8", identifier)
            elif self.path in ("/app.js", "/crypto.mjs", "/style.css"):
                mime = "text/css" if self.path.endswith(".css") else "text/javascript"
                self.reply(200, (WEB / self.path[1:]).read_bytes(), mime)
            elif self.path == "/api/status":
                _, session = self.session()
                self.reply(200, {"stage": session.stage, "csrf": session.csrf})
            else:
                self.reply(404, {"error": "Not found."})
        except ProbeError as exc:
            self.reply(403, {"error": str(exc)})

    def do_POST(self):
        try:
            self.gate(post=True)
            _, session = self.session()
            if self.headers.get_all("X-Probe-CSRF") != [session.csrf]:
                raise ProbeError("Invalid request token. Reload the page.")
            if self.headers.get_all("Content-Type") != ["application/json"] or self.headers.get("Transfer-Encoding"):
                raise ProbeError("Expected a bounded JSON request.")
            lengths = self.headers.get_all("Content-Length") or []
            if len(lengths) != 1 or not lengths[0].isdigit() or not 0 < int(lengths[0]) <= MAX_BODY:
                raise ProbeError("Invalid request length.")
            body = json.loads(self.rfile.read(int(lengths[0])))
            if not isinstance(body, dict):
                raise ProbeError("Expected a JSON object.")
            with session.lock:
                if self.path == "/api/begin":
                    result = self.server.probe.begin(session, body.get("action"))
                elif self.path == "/api/finish":
                    result = self.server.probe.finish(session, body.get("action"), body)
                else:
                    self.reply(404, {"error": "Not found."})
                    return
            self.reply(200, result)
        except ProbeError as exc:
            self.reply(400, {"error": str(exc)})
        except (ValueError, TypeError, OSError):
            self.reply(400, {"error": "Invalid request."})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=0, help="localhost port (default: choose a free port)")
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    with ProbeServer(args.port) as server:
        print(f"Open {server.origin}/ in your browser.", flush=True)
        print("Dummy data only. No kubeconfig, tokens, SSH files, or browser profile is read.", flush=True)
        print("Stop with Ctrl+C. The probe also stops automatically after 30 minutes.", flush=True)
        timer = threading.Timer(1800, server.shutdown)
        timer.daemon = True
        timer.start()
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            timer.cancel()


if __name__ == "__main__":
    main()
