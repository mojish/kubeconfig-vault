import io
import os
import subprocess
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from check_public_install import BASE, PublicInstall, VerificationError, native_archive, verify_release


class PublicInstallationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.check = PublicInstall("v1.2.3", root, time.monotonic() + 240)
        self.bytes = b"#!/bin/sh\necho kubeconfig-vault v1.2.3\n"

    def test_both_urls_and_anonymous_execution(self):
        calls = []
        real_run = self.check.run

        def run(*args, github=False):
            calls.append(args)
            if args[0] == "gh":
                self.assertTrue(github)
                return b"v1.2.3\n"
            self.assertFalse(github)
            if args[0] == "curl":
                dest = self.check.root / args[-2]
                if dest.name == self.check.archive:
                    with tarfile.open(dest, "w:gz") as out:
                        entry = tarfile.TarInfo("kube-unlock-age")
                        entry.size = len(self.bytes)
                        out.addfile(entry, io.BytesIO(self.bytes))
                else:
                    dest.write_text('set -eu\ntest -z "${GH_TOKEN:-}"\n'
                                    'cp expected "$1/kubeconfig-vault"\nchmod +x "$1/kubeconfig-vault"\n'
                                    'ln -s kubeconfig-vault "$1/kube-unlock-age"\n')
                return b""
            return real_run(*args)
        with patch.dict(os.environ, GH_TOKEN="synthetic"), patch.object(self.check, "run", side_effect=run):
            verify_release(self.check)
        self.assertEqual([x[-1] for x in calls if x[0] == "curl"],
                         [f"{BASE}/download/v1.2.3/{self.check.archive}", f"{BASE}/download/v1.2.3/install.sh",
                          f"{BASE}/latest/download/install.sh"])
        self.assertEqual(sum(x[:3] == ("gh", "release", "verify-asset") for x in calls), 3)

    def test_native_release_archives(self):
        for system, machine, target in [
            ("Linux", "x86_64", "linux-amd64"), ("Linux", "aarch64", "linux-arm64"),
            ("Darwin", "x86_64", "darwin-amd64"), ("Darwin", "arm64", "darwin-arm64"),
        ]:
            with self.subTest(target=target):
                self.assertEqual(native_archive(system, machine), f"kubeconfig-vault-{target}.tar.gz")
        with self.assertRaises(VerificationError):
            native_archive("Linux", "i686")

    def test_immutable_failure_cannot_be_skipped(self):
        with patch.object(self.check, "prepare", side_effect=VerificationError("corrupt")), \
             patch.object(self.check, "latest") as latest, patch("time.sleep"):
            with self.assertRaisesRegex(VerificationError, "archive verification failed"):
                verify_release(self.check)
            latest.assert_not_called()

    def test_latest_advances_during_download(self):
        calls = []
        def install(family):
            calls.append(family)
            if family == "latest":
                raise subprocess.CalledProcessError(22, "curl")
        with patch.object(self.check, "prepare"), patch.object(self.check, "install", side_effect=install), \
             patch.object(self.check, "latest", side_effect=["v1.2.3", "v1.2.4"]), patch("time.sleep"):
            verify_release(self.check)
        self.assertEqual(calls, ["tag", "latest"])

    def test_timeout_interrupts_installer_children(self):
        self.check.deadline = time.monotonic() + 0.2
        with self.assertRaises(subprocess.TimeoutExpired):
            self.check.run("sh", "-c", "(sleep 0.5 && touch survived) & wait")
        time.sleep(0.6)
        self.assertFalse((self.check.root / "survived").exists())

    def test_timeout_stops_before_execution(self):
        self.check.deadline = time.monotonic() - 1
        with patch("subprocess.Popen") as command:
            with self.assertRaisesRegex(VerificationError, "archive verification failed"):
                verify_release(self.check)
            command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
