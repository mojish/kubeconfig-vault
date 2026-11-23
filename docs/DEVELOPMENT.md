# Build, test, and release

Most users can [install the published binary](../README.md#install-and-set-up). This page is for contributors building the CLI or verifying a release. Use synthetic kubeconfigs, isolated browser profiles, and a loopback API for development tests.

## Build locally

Use Go 1.26.11 or newer and Node.js 22.12 or newer. Build the browser assets first because the Go executable embeds them. From the repository root:

```sh
cd age-app
npm ci --ignore-scripts --no-audit --no-fund
npm run build:web
go mod download
go build -o kubeconfig-vault .
./kubeconfig-vault --version
```

This leaves a development binary in `age-app/`. To install from a checkout, run `./install.sh --source` from the repository root. The installer accepts a final argument for a custom binary directory. With a bootstrap Go that supports toolchain downloads, `GOTOOLCHAIN=auto` lets Go select the required version.

## Run the checks

From `age-app/`, after building the browser assets:

```sh
go vet ./...
go test -race ./...
npm run test:ui
sh ../scripts/test-install.sh
python3 -B ../scripts/test_public_install.py
```

| Check | What it exercises |
| --- | --- |
| Go tests | Vault authentication, socket peer checks, session expiry, file permissions, interrupted edits, and safe repair under concurrent changes. |
| Browser UI tests | Pending browser prompts, completion, explicit decline, and stale status responses. |
| Installer tests | Archive checksums, version-pinned downloads, failed installation, and the public verification script using disposable fixtures. |

For an end-to-end run, install Chrome, kubectl, OpenSSL, and Python 3.9+ and run `npm run test:browser` from `age-app/`. The suite starts its own HTTPS API and temporary Chrome profile. A virtual USB authenticator exercises enrollment, unlock, concurrent requests, editing, repair and recovery. The suite first checks the generated client certificate with plain kubectl. It then tests a mixed token/certificate kubeconfig against an HTTPS bearer-token server and a second server requiring mutual TLS, including after offline recovery. Two deliberate waits of 61 seconds exercise credential expiry in a long-running client. The full integration test has a seven-minute limit.

Set `KUBE_UNLOCK_TEST_BINARY` to test a packaged executable. `KUBE_UNLOCK_TEST_CHROME` and `KUBE_UNLOCK_TEST_KUBECTL` select specific client executables. On Linux the suite uses the installed Freelens proxy when available, otherwise `kubectl proxy`. `KUBE_UNLOCK_TEST_FREELENS_PROXY` overrides its location.

Linux CI also runs `npm run audit:security`, which queries npm advisories and runs Go’s vulnerability checker. Native Go and browser tests run on Linux and both macOS architectures. [CI workflow](../.github/workflows/ci.yml)

## Test with a physical YubiKey

For the real Freelens GUI and Gatekeeper on macOS, use the [Mac test protocol](MACOS.md). For a kubectl hardware run on Linux or macOS, run these from the repo root with the same browser-test prerequisites and a USB security key:

```sh
node age-app/physical.test.mjs --preflight-only
node age-app/physical.test.mjs --keep-key-connected
```

The default test binary is `age-app/kubeconfig-vault`. Set `KUBE_UNLOCK_TEST_BINARY` to verify a specific download. Preflight checks the binary and runs kubectl against a dummy cluster without opening a browser. The hardware run prompts for enrollment and unlock, checks session reuse and offline recovery, and cleans up its temporary data. The key can stay connected throughout.

## Prepare a release

The packaging script runs on Linux, requires a new output directory, and builds Linux and macOS archives for amd64 and arm64. To rehearse locally, use a disposable directory and a test version:

```sh
scratch=$(mktemp -d)
./scripts/package-release.sh v0.0.0 "$scratch/assets"
sh install.sh --from-dir "$scratch/assets" "$scratch/bin"
"$scratch/bin/kubeconfig-vault" --version
```

For a real release, pushing a `vMAJOR.MINOR.PATCH` tag starts the release workflow. It runs CI, builds the four archives, installs them on their target platforms, and checks the checksum manifest. Packaged browser integration runs on Linux x86-64 and both Mac targets. The workflow attests the artifacts and creates a draft. Review the tag, notes, and all six assets before publishing. [Release workflow](../.github/workflows/release.yml)

On publication, a separate job anonymously downloads the Linux x86-64 installer and archive, verifies their release provenance, installs in a temporary home, and checks the binary bytes, version, and compatibility link. It tries the immutable tag first and the README’s latest URL while that tag is current. For tagged installers from v0.3.1 onward, use the workflow’s manual tag input to repeat the check. [Public installation workflow](../.github/workflows/public-install.yml)

To verify a downloaded archive against its build attestation, run `gh attestation verify kubeconfig-vault-linux-amd64.tar.gz --repo mojish/kubeconfig-vault`. To install downloaded assets offline, place the matching archive and `SHA256SUMS` in one directory and run `sh install.sh --from-dir DIRECTORY` using the published installer.
