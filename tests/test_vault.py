import copy
import json
from pathlib import Path
import secrets
import tempfile
import time
import unittest
from unittest.mock import patch

import yaml

from runtime import Runtime, session_clock
from vault_core import Store, VaultError, cluster_binding, prepare

SAMPLE = """# Preserve my comments.
apiVersion: v1
kind: Config
clusters:
- name: example
  cluster:
    server: https://example.invalid
users:
- name: example-user
  user:
    token: synthetic-token-for-tests-only
contexts:
- name: example-context
  context:
    cluster: example
    user: example-user
current-context: example-context
"""


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kube-unlock-unit-")
        self.root = Path(self.temp.name)
        self.store = Store(self.root / "state")
        self.key = secrets.token_bytes(32)
        self.payload = prepare(SAMPLE, self.root, self.store.path)

    def tearDown(self):
        self.temp.cleanup()

    def test_encryption_roundtrip_and_plaintext_absence(self):
        generation = self.store.commit(self.payload, self.key, [])
        restored = self.store.decrypt(self.store.current()[1], self.key)
        self.assertEqual(restored["text"], SAMPLE)
        self.assertEqual(restored["records"]["example-user"]["token"], "synthetic-token-for-tests-only")
        for path in (self.store.generations / generation).iterdir():
            self.assertNotIn(b"synthetic-token-for-tests-only", path.read_bytes())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_wrong_key_and_modified_ciphertext_rejected(self):
        self.store.commit(self.payload, self.key, [])
        document = self.store.current()[1]
        with self.assertRaises(VaultError):
            self.store.decrypt(document, secrets.token_bytes(32))
        document["ciphertext"] = "A" + document["ciphertext"][1:]
        with self.assertRaises(VaultError):
            self.store.decrypt(document, self.key)

    def test_conflict_preserves_current(self):
        initial = self.store.commit(self.payload, self.key, [])
        with self.assertRaises(VaultError):
            self.store.commit(self.payload, self.key, [], expected="incorrect")
        self.assertEqual(self.store.current()[0], initial)

    def test_generations_are_bounded_and_restorable(self):
        previous = None
        for _ in range(7):
            previous = self.store.commit(self.payload, self.key, [], expected=previous)
        directories = list(self.store.generations.iterdir())
        self.assertEqual(len(directories), 4)
        for directory in directories:
            data = json.loads((directory / "vault.json").read_text())
            self.assertEqual(self.store.decrypt(data, self.key)["text"], SAMPLE)

    def test_rejects_duplicate_keys_names_and_unsupported_auth(self):
        bad = [SAMPLE + "kind: Config\n", SAMPLE.replace("token: synthetic-token-for-tests-only", "exec: {command: arbitrary}"),
               SAMPLE.replace("- name: example-user", "- name: example-user\n  user: {token: fake}\n- name: example-user")]
        for text in bad:
            with self.subTest(text=text[:30]), self.assertRaises(VaultError):
                prepare(text, self.root, self.store.path)

    def test_relative_public_ca_is_embedded_and_source_preserved(self):
        (self.root / "ca.pem").write_text("dummy public CA")
        text = SAMPLE.replace("server: https://example.invalid", "server: https://example.invalid\n    certificate-authority: ca.pem")
        payload = prepare(text, self.root, self.store.path)
        self.assertEqual(payload["text"], text)
        self.assertIn("certificate-authority-data", payload["generated"]["clusters"][0]["cluster"])

    def test_token_files_require_explicit_selection(self):
        (self.root / "token.txt").write_text("synthetic-from-file\n")
        text = SAMPLE.replace("token: synthetic-token-for-tests-only", "tokenFile: token.txt")
        with self.assertRaises(VaultError):
            prepare(text, self.root, self.store.path)
        result = prepare(text, self.root, self.store.path, token_files=True)
        self.assertEqual(result["records"]["example-user"]["token"], "synthetic-from-file")

    def test_token_file_snapshot_survives_source_file_removal(self):
        path = self.root / "token.txt"
        path.write_text("synthetic-from-file\n")
        text = SAMPLE.replace("token: synthetic-token-for-tests-only", "tokenFile: token.txt")
        original = prepare(text, self.root, self.store.path, token_files=True)
        path.unlink()
        edited = prepare(text + "# ordinary edit\n", self.root, self.store.path, previous=original, token_files=True)
        self.assertEqual(edited["records"]["example-user"]["token"], "synthetic-from-file")

    def test_interrupted_save_keeps_matching_previous_generation(self):
        from vault_core import write_private
        initial = self.store.commit(self.payload, self.key, [])
        def fail_connection_file(path, data):
            if path.name == "kubeconfig":
                raise OSError("synthetic disk failure")
            return write_private(path, data)
        with patch("vault_core.write_private", side_effect=fail_connection_file), self.assertRaises(OSError):
            self.store.commit(self.payload, self.key, [], expected=initial)
        self.assertEqual(self.store.current()[0], initial)
        self.assertEqual(self.store.decrypt(self.store.current()[1], self.key), self.payload)

    def test_prune_failure_does_not_report_committed_save_as_failed(self):
        previous = None
        for _ in range(4):
            previous = self.store.commit(self.payload, self.key, [], expected=previous)
        with patch("vault_core.shutil.rmtree", side_effect=OSError("synthetic cleanup failure")):
            committed = self.store.commit(self.payload, self.key, [], expected=previous)
        self.assertEqual(self.store.current()[0], committed)

    def test_binding_covers_trust_proxy_and_destination(self):
        original = {"server": "https://example.invalid"}
        for key, value in [("server", "https://other.invalid"), ("certificate-authority-data", "dummy"),
                           ("insecure-skip-tls-verify", True), ("tls-server-name", "other.invalid"), ("proxy-url", "http://example.invalid")]:
            self.assertNotEqual(cluster_binding(original), cluster_binding({**original, key: value}))
        self.assertEqual(cluster_binding(original), cluster_binding({**original, "insecure-skip-tls-verify": False}))


class RuntimeTests(VaultTests):
    def setUp(self):
        super().setUp()
        self.store.commit(self.payload, self.key, [])
        self.runtime = Runtime(self.store.path, browser=False, runtime_dir=self.root)
        self.reopen()

    def reopen(self):
        self.runtime.key = bytearray(self.key)
        self.runtime.payload = self.store.decrypt(self.store.current()[1], self.key)
        self.runtime.deadline = session_clock() + 3600
        self.runtime.expires = time.time() + 3600

    def tearDown(self):
        self.runtime.server.server_close()
        self.runtime.clear()
        super().tearDown()

    def test_token_selection_and_fixed_expiry(self):
        body = {"operation": "credential", "identity": self.payload["records"]["example-user"]["id"],
                "cluster": {"server": "https://example.invalid"}}
        a = self.runtime.request(body)
        b = self.runtime.request(body)
        self.assertEqual(a["status"], b["status"])
        with self.assertRaises(VaultError):
            self.runtime.request({**body, "cluster": {"server": "https://other.invalid"}})

    def test_expiration_drops_key_and_payload(self):
        self.runtime.deadline = time.monotonic() - 1
        self.runtime.expire()
        self.assertIsNone(self.runtime.key)
        self.assertIsNone(self.runtime.payload)

    def test_suspend_time_counts_toward_session_expiration(self):
        with patch("runtime.session_clock", return_value=self.runtime.deadline + 1):
            self.runtime.expire()
        self.assertIsNone(self.runtime.key)

    def test_edit_roundtrip_and_lock(self):
        path = Path(self.runtime.request({"operation": "config-unlock"})["path"])
        changed = path.read_text() + "# Added in a normal editor.\n"
        path.write_text(changed)
        self.runtime.request({"operation": "config-lock"})
        self.assertFalse(path.exists())
        self.assertIsNone(self.runtime.key)
        self.assertEqual(self.store.decrypt(self.store.current()[1], self.key)["text"], changed)

    def test_invalid_edit_preserves_copy_and_original(self):
        generation = self.store.current()[0]
        path = Path(self.runtime.request({"operation": "config-unlock"})["path"])
        path.write_text("{broken")
        with self.assertRaises(VaultError):
            self.runtime.request({"operation": "config-lock"})
        self.assertTrue(path.exists())
        self.assertEqual(self.store.current()[0], generation)

    def test_destination_change_requires_explicit_acceptance(self):
        path = Path(self.runtime.request({"operation": "config-unlock"})["path"])
        path.write_text(path.read_text().replace("https://example.invalid", "https://other.invalid"))
        with self.assertRaises(VaultError):
            self.runtime.request({"operation": "config-lock"})
        self.runtime.request({"operation": "config-lock", "accept_connections": True})

    def test_generated_auth_edits_detected(self):
        path = self.store.path / "current" / "kubeconfig"
        config = yaml.safe_load(path.read_text())
        config["users"][0]["user"] = {"token": "dummy-tampering"}
        path.write_text(yaml.safe_dump(config))
        with self.assertRaises(VaultError):
            self.runtime.request({"operation": "config-unlock"})

    def test_context_namespace_selection_survives_save(self):
        path = self.store.path / "current" / "kubeconfig"
        config = yaml.safe_load(path.read_text())
        config["contexts"][0]["context"]["namespace"] = "selected"
        path.write_text(yaml.safe_dump(config))
        self.runtime.request({"operation": "config-unlock"})
        self.runtime.request({"operation": "config-lock"})
        updated = yaml.safe_load(path.read_text())
        self.assertEqual(updated["contexts"][0]["context"]["namespace"], "selected")

    def test_discard_plaintext_is_available_while_locked(self):
        path = Path(self.runtime.request({"operation": "config-unlock"})["path"])
        self.runtime.clear()
        self.runtime.request({"operation": "config-discard"})
        self.assertFalse(path.exists())

    def test_cleared_namespace_selection_survives_save(self):
        original = SAMPLE.replace("    user: example-user", "    user: example-user\n    namespace: original")
        self.payload = prepare(original, self.root, self.store.path)
        self.store.commit(self.payload, self.key, [], expected=self.store.current()[0])
        self.reopen()
        path = self.store.path / "current" / "kubeconfig"
        config = yaml.safe_load(path.read_text())
        config["contexts"][0]["context"].pop("namespace")
        path.write_text(yaml.safe_dump(config))
        self.runtime.request({"operation": "config-unlock"})
        self.runtime.request({"operation": "config-lock"})
        self.assertNotIn("namespace", yaml.safe_load(path.read_text())["contexts"][0]["context"])

    def test_stop_clears_session_and_signals_shutdown(self):
        self.runtime.request({"operation": "stop"})
        self.assertTrue(self.runtime.stopping.is_set())
        self.assertIsNone(self.runtime.key)

    def test_cleanup_failure_after_save_still_locks_credentials(self):
        path = Path(self.runtime.request({"operation": "config-unlock"})["path"])
        path.write_text(path.read_text() + "# persisted despite cleanup failure\n")
        with patch("pathlib.Path.unlink", side_effect=OSError("synthetic cleanup failure")), self.assertRaises(OSError):
            self.runtime.request({"operation": "config-lock"})
        self.assertIsNone(self.runtime.key)
        self.assertIn("persisted despite cleanup failure", self.store.decrypt(self.store.current()[1], self.key)["text"])

    # Core tests run once in VaultTests rather than against an initialized runtime.
    test_encryption_roundtrip_and_plaintext_absence = None
    test_wrong_key_and_modified_ciphertext_rejected = None
    test_conflict_preserves_current = None
    test_generations_are_bounded_and_restorable = None
    test_interrupted_save_keeps_matching_previous_generation = None
    test_prune_failure_does_not_report_committed_save_as_failed = None


if __name__ == "__main__":
    unittest.main()
