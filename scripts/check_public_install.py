"""Verify a published Linux installer using anonymous downloads and a disposable home."""
import filecmp
import os
import re
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from shutil import copyfileobj

REPO = "mojish/kubeconfig-vault"
BASE = f"https://github.com/{REPO}/releases"
ARCHIVE = "kubeconfig-vault-linux-amd64.tar.gz"


class VerificationError(Exception):
    pass


class PublicInstall:
    def __init__(self, tag, root, deadline):
        self.tag = tag
        self.root = root
        self.deadline = deadline
        self.public_env = {"PATH": os.environ["PATH"], "HOME": str(root)}

    def run(self, *args, github=False):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("public verification deadline reached")
        with subprocess.Popen(args, cwd=self.root, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              start_new_session=True, env=None if github else self.public_env) as process:
            try:
                stdout, _ = process.communicate(timeout=min(60, remaining))
            except subprocess.TimeoutExpired:
                # The installer can have curl/tar children. Stop the entire attempt.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.communicate()
                raise
            if process.returncode:
                raise subprocess.CalledProcessError(process.returncode, args)
            return stdout

    def get(self, url, file):
        self.run("curl", "-q", "-fsSL", "--proto", "=https", "--proto-redir", "=https",
                 "--connect-timeout", "10", "-o", file, url)

    def latest(self):
        return self.run("gh", "api", f"repos/{REPO}/releases/latest",
                        "--jq", ".tag_name", github=True).decode().strip()

    def verify(self, file):
        self.run("gh", "release", "verify-asset", self.tag, file, "-R", REPO, github=True)

    def prepare(self):
        self.get(f"{BASE}/download/{self.tag}/{ARCHIVE}", ARCHIVE)
        self.verify(ARCHIVE)
        with tarfile.open(self.root / ARCHIVE, "r:gz") as archive:
            with archive.extractfile("kube-unlock-age") as member, (self.root / "expected").open("wb") as out:
                copyfileobj(member, out)

    def install(self, family):
        url = f"{BASE}/download/{self.tag}" if family == "tag" else f"{BASE}/latest/download"
        self.get(f"{url}/install.sh", "install.sh")
        self.verify("install.sh")
        # Only execute the release-attested script. Its downloads get a fresh
        # home and no GitHub authentication. Check bytes before running binaries.
        with tempfile.TemporaryDirectory(dir=self.root) as directory:
            self.run("sh", "install.sh", directory)
            binary = Path(directory) / "kubeconfig-vault"
            alias = binary.with_name("kube-unlock-age")
            if binary.is_symlink() or not filecmp.cmp(binary, self.root / "expected", shallow=False):
                raise VerificationError("installed binary differs from the verified archive")
            if os.readlink(alias) != binary.name:
                raise VerificationError("incorrect compatibility link")
            for executable in [binary, alias]:
                if self.run(executable, "--version").decode().strip() != f"kubeconfig-vault {self.tag}":
                    raise VerificationError("unexpected installed version")


def verify_release(test):
    # The tag is mandatory. A newer latest release may appear between any two
    # requests. Recheck after a failure before deciding the latest family failed.
    for family in ["archive", "tag", "latest"]:
        for attempt in range(4):
            try:
                if family == "latest" and test.latest() != test.tag:
                    print("Skipped latest URL because a different release is latest.")
                    return
                if family == "archive":
                    test.prepare()
                else:
                    test.install(family)
                print(f"Verified {family} for {test.tag}.", flush=True)
                break
            except (VerificationError, subprocess.SubprocessError, OSError, tarfile.TarError, KeyError) as err:
                # Every retry starts by checking latest. On the last failure
                # check once more in case a newer release just won the race.
                if family == "latest" and attempt == 3 and test.latest() != test.tag:
                    print("Skipped latest URL because it changed during verification.")
                    return
                if attempt == 3 or time.monotonic() + 5 >= test.deadline:
                    raise VerificationError(f"{family} verification failed: {err}") from err
                time.sleep(5)


if __name__ == "__main__":
    if len(sys.argv) != 2 or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", sys.argv[1]):
        sys.exit("Supply a release tag such as v0.4.0.")
    with tempfile.TemporaryDirectory(prefix="kcv-public-") as root:
        verify_release(PublicInstall(sys.argv[1], Path(root), time.monotonic() + 240))
