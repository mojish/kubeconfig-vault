# Development and testing

## Installation options

`./install.sh` downloads and checks the latest published archive for your OS
and CPU. The same installer works without a checkout when downloaded from the
release. A published installer fetches both the checksum manifest and archive
from its embedded release tag. A checkout resolves GitHub's latest tag once.
To install an archive you've already downloaded, put the archive and
`SHA256SUMS` in the same directory and run:

```sh
sh install.sh --from-dir "$HOME/Downloads"
```

For a source build or when no release is published, clone this repo and run
`./install.sh --source`. It checks `age-app/go.mod` before installing npm packages.
You need Go 1.26.11 or newer and Node.js 22.12 or newer. With an older bootstrap
Go that supports automatic toolchains, `GOTOOLCHAIN=auto ./install.sh --source`
allows Go to download the required version. A final argument selects a custom
install directory.

The macOS binaries are experimental and have not been notarized by Apple.
If [Gatekeeper](https://support.apple.com/en-us/102445) blocks a download, build
from source. The hosted checks run the packaged CLI; desktop browser launch
and physical YubiKey testing on macOS remain separate checks.

## Build and test locally

For development, build and test in `age-app`.

```sh
cd age-app
npm ci --ignore-scripts --no-audit --no-fund
npm run build:web
go mod download
go build -o kubeconfig-vault .
go test -race ./...
go vet ./...
npm run test:ui
npm run test:browser
sh ../scripts/test-install.sh
python3 -B ../scripts/test_public_install.py
npm run audit:security
```

The browser test uses isolated Chrome with virtual FIDO2, real kubectl, and a
local HTTPS API. It needs Chrome, kubectl, OpenSSL, and Python 3.9 or newer for
the pseudo-terminal test of the displayed and pasted synthetic key. Set
`KUBE_UNLOCK_TEST_CHROME` or `KUBE_UNLOCK_TEST_KUBECTL` to override the executables.
The optional Freelens proxy check uses `KUBE_UNLOCK_TEST_FREELENS_PROXY` or the
installed Linux proxy. Without it, the suite uses a long-lived `kubectl proxy`.
It counts exec-plugin calls and browser launches across two one-minute refreshes,
including a manual lock. A separate two-context test dismisses one request and
checks that the queued request shares its result. All tests use synthetic
credentials and disposable state.

The browser suite also rewrites the linked file with real kubectl before cold
and cached requests, saves an edit, and checks the selected context and namespace
afterward. The installer test uses a disposable download fixture to verify
the exact release URLs and that a checksum failure preserves the installed binary.

The Go suite covers session expiry, Unix peer identity, authenticated storage,
file handling, editing failures, and HTTP access controls. The Linux
process-argument test uses procfs and `/usr/bin/python3`. `test:ui` checks that
browser polling and click responses keep the correct page state.

[CI](https://github.com/mojish/kubeconfig-vault/actions/workflows/ci.yml) runs
native Go and UI tests on Ubuntu and both macOS architectures. The browser integration runs on Ubuntu and macOS. Ubuntu also runs `npm audit` and `govulncheck`. The advisory checks
need public package and vulnerability services. Review called symbols separately
from matches in unused module packages. CI uses pinned actions, read-only
permissions, and no configured secrets. Dependabot proposes dependency updates.

## Test with a physical YubiKey

To test a **published macOS release** with a USB key and the Freelens desktop
app, follow the [Mac volunteer guide](MACOS.md). It includes a first-launch
Gatekeeper check and uses a synthetic cluster in a disposable account.

For the kubectl hardware test on Linux or macOS, run these commands from the
repository root with Node.js 22.12+, Chrome, kubectl, and OpenSSL available.
Set `KUBE_UNLOCK_TEST_BINARY` to the absolute path of a published executable,
or build `age-app/kubeconfig-vault` using the commands above.

```sh
node age-app/physical.test.mjs --preflight-only
node age-app/physical.test.mjs --keep-key-connected
```

Preflight checks the executable version and verifies kubectl against a dummy
HTTPS API without a key. The full run opens
isolated Chrome and asks you to complete enrollment and then a separate unlock.
The blank Chrome startup window needs no action. Use your USB key and enter its
PIN only in Chrome’s prompt. The check covers import, cold unlock, cached access,
and offline recovery with the key left connected. Ctrl+C or the test deadline
ends the run and cleans up its temporary profile, vault, and recovery key.

Linux has passed this hardware flow. An isolated Freelens 2.1.0 GUI test on Linux
also passed cluster discovery, first unlock, session sharing with kubectl, and
reconnect after a saved edit. That test used a virtual security key and a dummy
API. Desktop browser launch and USB key use on macOS still need hands-on testing.

## Interrupted edits

Close the editor before `config lock`. Connection and trust changes require
`config lock --accept-connection-changes` after reviewing them. Validation
failures retain the edit. If a save reports that the file changed before commit,
close the editor and retry.

If the vault was committed but cleanup failed, run `status` and examine every
entry in `edit_paths`. Preserve any changes you want in a private file. Then run
`config discard` to clear the edit paths, unlock a fresh edit, merge your changes,
and save again. `config discard` deletes both the edit and the interrupted-save
copy. Ordinary lock and stop preserve them.

For offline recovery, follow the [README](../README.md#back-up-and-recover). If you
replace a lost YubiKey, import the recovered plaintext into a new state directory
with the replacement key and verify it before switching clients. Select the new
state directory with `--state-dir PATH` before the `import` command.

## Prepare a release

On Linux, build release assets into a new directory without creating a tag:

```sh
./scripts/package-release.sh v0.1.0 /tmp/kubeconfig-vault-release
sh install.sh --from-dir /tmp/kubeconfig-vault-release /tmp/kubeconfig-vault-bin
/tmp/kubeconfig-vault-bin/kubeconfig-vault --version
```

The [release workflow](../.github/workflows/release.yml) runs for version tags
such as `v0.1.0`. It runs the regular CI suite, makes four tarballs, and tests
the exact archives by installing them and running `--version` on Ubuntu and
macOS on x86-64 and ARM64. With `KUBE_UNLOCK_TEST_BINARY` set to the installed
executable, the browser integration also exercises those packages on Linux x86-64
and both Mac targets. After success it checks the complete checksum
manifest, attaches GitHub build attestations, and creates a draft release.
A maintainer reviews and publishes the draft.

For provenance beyond the installer's checksum check, use GitHub CLI to verify a
downloaded archive against the repository's build attestation:

```sh
gh attestation verify kubeconfig-vault-linux-amd64.tar.gz --repo mojish/kubeconfig-vault
```


The **Verify public installation** workflow runs after publication. It verifies
the Linux x86-64 archive and installer with `gh release verify-asset`, runs
the anonymously downloaded installer in a temporary home, compares the installed
bytes with the verified archive, and checks both executable names. It tests the
tagged download first, then the README's latest URL while the tag is current.
Use the workflow's manual tag input to repeat the check for v0.3.1 or newer. Earlier installers always selected the latest archive.
