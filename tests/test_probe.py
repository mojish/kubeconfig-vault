import hashlib
import http.client
import json
import secrets
import threading
import time
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2.cose import ES256
from fido2.webauthn import AttestationObject, AttestedCredentialData, AuthenticatorData, CollectedClientData

from probe import CHALLENGE_TTL, MAX_BODY, MAX_SESSIONS, SESSION_TTL, Probe, ProbeError, ProbeServer, decode, encode


class Authenticator:
    """Synthetic signing key, never reads a device or file."""

    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.identifier = secrets.token_bytes(32)
        self.credential = AttestedCredentialData.create(bytes(16), self.identifier, ES256.from_cryptography_key(self.key.public_key()))

    def response(self, options, origin, register=False, flags=5, rp="localhost", cross_origin=False):
        client = CollectedClientData.create(
            "webauthn.create" if register else "webauthn.get",
            options["publicKey"]["challenge"], origin, cross_origin=cross_origin,
        )
        auth = AuthenticatorData.create(
            hashlib.sha256(rp.encode()).digest(), flags | (64 if register else 0), 0,
            self.credential if register else b"",
        )
        result = {
            "id": encode(self.identifier), "rawId": encode(self.identifier), "type": "public-key",
            "authenticatorAttachment": "cross-platform", "response": {"clientDataJSON": encode(client)},
        }
        if register:
            result["response"]["attestationObject"] = encode(AttestationObject.create("none", auth, {}))
        else:
            result["response"].update({
                "authenticatorData": encode(auth),
                "signature": encode(self.key.sign(auth + client.hash, ec.ECDSA(hashes.SHA256()))),
            })
        return result


class Ceremonies(unittest.TestCase):
    def setUp(self):
        self.probe = Probe("http://localhost:8765")
        self.cookie, self.session = self.probe.get_session(create=True)
        self.auth = Authenticator()

    def registration(self, **kwargs):
        request = self.probe.begin(self.session, "register")
        return {
            "request": request["request"], "prfEnabled": True,
            "credential": self.auth.response(request["options"], self.probe.origin, register=True, **kwargs),
        }

    def register(self):
        self.probe.finish(self.session, "register", self.registration())

    def assertion(self, action="seal", auth=None, **kwargs):
        request = self.probe.begin(self.session, action)
        response = (auth or self.auth).response(request["options"], self.probe.origin, **kwargs)
        return {"request": request["request"], "credential": response}

    def envelope(self):
        # Protocol shape only. Actual encryption is tested in Node and Chrome.
        return {"iv": encode(bytes(12)), "ciphertext": encode(bytes(64))}

    def test_complete_flow(self):
        self.register()
        body = self.assertion()
        body["envelope"] = self.envelope()
        self.probe.finish(self.session, "seal", body)
        body = self.assertion("open")
        body["sample"] = encode(self.session.sample)
        self.assertEqual(self.probe.finish(self.session, "open", body), {"stage": "passed"})

    def test_registration_requires_user_verification(self):
        with self.assertRaises(ProbeError):
            self.probe.finish(self.session, "register", self.registration(flags=1))

    def test_registration_requires_presence(self):
        with self.assertRaises(ProbeError):
            self.probe.finish(self.session, "register", self.registration(flags=4))

    def test_registration_requires_prf(self):
        body = self.registration()
        body["prfEnabled"] = False
        with self.assertRaisesRegex(ProbeError, "PRF"):
            self.probe.finish(self.session, "register", body)

    def test_registration_rejects_platform_key(self):
        body = self.registration()
        body["credential"]["authenticatorAttachment"] = "platform"
        with self.assertRaisesRegex(ProbeError, "physical USB"):
            self.probe.finish(self.session, "register", body)

    def test_cross_origin_ceremony_rejected(self):
        with self.assertRaises(ProbeError):
            self.probe.finish(self.session, "register", self.registration(cross_origin=True))

    def test_wrong_rp_rejected(self):
        with self.assertRaises(ProbeError):
            self.probe.finish(self.session, "register", self.registration(rp="example.invalid"))

    def test_wrong_origin_rejected(self):
        request = self.probe.begin(self.session, "register")
        body = {"request": request["request"], "prfEnabled": True,
                "credential": self.auth.response(request["options"], "http://localhost:8766", register=True)}
        with self.assertRaises(ProbeError):
            self.probe.finish(self.session, "register", body)

    def test_challenge_replacement_invalidates_response(self):
        body = self.registration()
        self.probe.begin(self.session, "register")
        with self.assertRaises(ProbeError):
            self.probe.finish(self.session, "register", body)

    def test_expired_challenge_rejected(self):
        body = self.registration()
        action, identifier, state, started = self.session.pending
        self.session.pending = action, identifier, state, started - CHALLENGE_TTL - 1
        with self.assertRaisesRegex(ProbeError, "expired"):
            self.probe.finish(self.session, "register", body)

    def test_replay_rejected(self):
        body = self.registration()
        self.probe.finish(self.session, "register", body)
        with self.assertRaisesRegex(ProbeError, "No pending"):
            self.probe.finish(self.session, "register", body)

    def test_wrong_key_cannot_authenticate(self):
        self.register()
        with self.assertRaises(ProbeError):
            self.probe.finish(self.session, "seal", self.assertion(auth=Authenticator()))

    def test_tampered_signature_rejected(self):
        self.register()
        body = self.assertion()
        body["credential"]["response"]["signature"] = encode(bytes(70))
        with self.assertRaises(ProbeError):
            self.probe.finish(self.session, "seal", body)

    def test_assertion_requires_verification_and_presence(self):
        self.register()
        for flags in [0, 1, 4]:
            with self.subTest(flags=flags), self.assertRaises(ProbeError):
                self.probe.finish(self.session, "seal", self.assertion(flags=flags))

    def test_wrong_plaintext_does_not_pass(self):
        self.register()
        body = self.assertion()
        body["envelope"] = self.envelope()
        self.probe.finish(self.session, "seal", body)
        body = self.assertion("open")
        body["sample"] = encode(bytes(48))
        with self.assertRaisesRegex(ProbeError, "did not match"):
            self.probe.finish(self.session, "open", body)
        self.assertEqual(self.session.stage, "sealed")

    def test_malformed_envelope_does_not_advance(self):
        self.register()
        body = self.assertion()
        body["envelope"] = {"iv": "", "ciphertext": ""}
        with self.assertRaises(ProbeError):
            self.probe.finish(self.session, "seal", body)
        self.assertEqual(self.session.stage, "registered")

    def test_stage_cannot_be_skipped(self):
        for action in ["seal", "open", "unknown"]:
            with self.subTest(action=action), self.assertRaises(ProbeError):
                self.probe.begin(self.session, action)

    def test_session_expiry_and_capacity(self):
        self.session.created -= SESSION_TTL + 1
        with self.assertRaises(ProbeError):
            self.probe.get_session(self.cookie)
        for _ in range(MAX_SESSIONS):
            self.probe.get_session(create=True)
        with self.assertRaises(ProbeError):
            self.probe.get_session(create=True)


class HTTPBoundary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ProbeServer()
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def request(self, method, path, body=None, headers=None):
        client = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        base = {"Host": self.server.origin.removeprefix("http://")}
        base.update(headers or {})
        client.request(method, path, body=body, headers=base)
        response = client.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        client.close()
        return result

    def session_headers(self):
        status, headers, _ = self.request("GET", "/")
        self.assertEqual(status, 200)
        cookie = headers["Set-Cookie"].split(";")[0]
        _, _, data = self.request("GET", "/api/status", headers={"Cookie": cookie})
        return {"Cookie": cookie, "Origin": self.server.origin, "Content-Type": "application/json",
                "X-Probe-CSRF": json.loads(data)["csrf"]}

    def test_loopback_only_and_no_store(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")
        _, headers, _ = self.request("GET", "/")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertIn("HttpOnly", headers["Set-Cookie"])

    def test_unrelated_host_and_cross_site_rejected(self):
        for headers in [{"Host": "evil.invalid"}, {"Sec-Fetch-Site": "cross-site"}, {"Sec-Fetch-Site": "same-site"}]:
            with self.subTest(headers=headers):
                self.assertEqual(self.request("GET", "/", headers=headers)[0], 403)

    def test_no_session_cannot_access_state(self):
        self.assertEqual(self.request("GET", "/api/status")[0], 403)

    def test_post_requires_origin_csrf_and_content_type(self):
        headers = self.session_headers()
        for key, value in [("Origin", "http://evil.invalid"), ("X-Probe-CSRF", "incorrect"), ("Content-Type", "text/plain")]:
            with self.subTest(key=key):
                invalid = {**headers, key: value}
                self.assertEqual(self.request("POST", "/api/begin", '{"action":"register"}', invalid)[0], 400)

    def test_post_bounds_and_malformed_json(self):
        headers = self.session_headers()
        for body in ["x" * (MAX_BODY + 1), "{bad", "[]", "null"]:
            self.assertEqual(self.request("POST", "/api/begin", body, headers)[0], 400)

    def test_valid_begin_and_no_file_routes(self):
        headers = self.session_headers()
        status, _, body = self.request("POST", "/api/begin", '{"action":"register"}', headers)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["options"]["publicKey"]["authenticatorSelection"]["userVerification"], "required")
        for path in ["/../probe.py", "/kubeconfig", "/api/token", "/?file=anything"]:
            self.assertEqual(self.request("GET", path)[0], 404)


if __name__ == "__main__":
    unittest.main()
