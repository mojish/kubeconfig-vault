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

After building the browser assets, run the Go benchmarks from `age-app/`. `go test -run '^$' -bench 'Benchmark(PreserveSelections|WarmCredentialDelivery)' -benchmem` measures saving existing context selections and delivering a cached credential with 10, 100, and 1,000 contexts. The warm-delivery fixture shares one cluster and credential across its contexts and includes the helper’s filesystem checks.

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

For an end-to-end run, install Go, Chrome, kubectl, OpenSSL, and Python 3.9+ and run `npm run test:browser` from `age-app/`. The suite starts its own HTTPS API and temporary Chrome profile. A virtual USB authenticator exercises enrollment, unlock, concurrent requests, editing, repair and recovery. The suite generates a temporary client CA and leaf with Go, verifies the chain with OpenSSL and checks the credential with plain kubectl. It then tests a mixed token/certificate kubeconfig against an HTTPS bearer-token server and a second server requiring mutual TLS, including after offline recovery. For lost-key recovery the test stops the old helper, moves its state aside and removes the original virtual authenticator. It checks that an unrelated offline key fails before enrollment, restores a backup with a newly created authenticator, and verifies two authenticated kubectl requests after one fresh approval. Two deliberate waits of 61 seconds exercise credential expiry in a long-running client. The full integration test has a seven-minute limit.

Set `KUBE_UNLOCK_TEST_BINARY` to test a packaged executable. `KUBE_UNLOCK_TEST_CHROME` and `KUBE_UNLOCK_TEST_KUBECTL` select specific client executables. On Linux the suite uses the installed Freelens proxy when available, otherwise `kubectl proxy`. `KUBE_UNLOCK_TEST_FREELENS_PROXY` overrides its location.

To exercise the default session for a full hour on an awake machine, run `npm run test:browser -- --one-hour-session`. Six fresh kubectl processes must reach the fixture API without extending the original deadline or opening another page. After expiry, two requests must share exactly one new approval. Allow about 65 minutes. To run this on a hosted runner, open the CI workflow, choose **Run workflow**, and select one platform for the full-hour trial. The ordinary suite exercises expiry with a short session.

Pull requests and pushes to main run native Go and browser tests on both CPU architectures for Linux and macOS. You can dispatch the workflow manually for a branch. The Linux ARM64 runner installs stable Chrome through Google's signed APT repository. Linux x86-64 also tests the previous binary and runs `npm run audit:security`, which checks npm and Go advisories. [CI workflow](../.github/workflows/ci.yml)

### Test the Freelens desktop with a virtual key

Enable the Freelens desktop option when manually running CI. Each runner verifies the pinned SHA-256 digest for its official desktop package. Linux installs the Debian package on the temporary runner and uses a private virtual display. The Mac runners mount the disk image read-only. The app opens a disposable kubeconfig and profile and the test controls the window over a private process pipe. Run this desktop test on a disposable OS account or VM. A separate app profile alone does not isolate the desktop from your account. The first case requires Freelens to display a certificate-authenticated namespace during kubectl’s session. The second reopens Freelens after locking and requires one fresh approval. Each case checks the API request and the actual namespace row. [Freelens 2.1.0 release](https://github.com/freelensapp/freelens/releases/tag/v2.1.0)

## Test with a physical YubiKey

For the real Freelens GUI and Gatekeeper on macOS, use the [Mac test protocol](MACOS.md). For a kubectl hardware run on Linux or macOS, run these from the repo root with the same browser-test prerequisites and a USB security key:

```sh
node age-app/physical.test.mjs --preflight-only
node age-app/physical.test.mjs --keep-key-connected
```

To exercise embedded certificates, use the fixture from a checkout with Go available. Both commands generate a new client CA and key pair inside the test directory.

```sh
node age-app/physical.test.mjs --preflight-only --client-certificate
node age-app/physical.test.mjs --keep-key-connected --client-certificate
```

The first command makes real kubectl requests against a loopback API that requires the generated client certificate. It also tries a client without the certificate and checks that the request fails. The second uses the same type of API to test enrollment, session reuse and recovery with a physical key.

The default test binary is `age-app/kubeconfig-vault`. Set `KUBE_UNLOCK_TEST_BINARY` to verify a specific download. Preflight checks the binary and runs kubectl against a dummy cluster without opening a browser. The hardware run prompts for enrollment and unlock, checks session reuse and offline recovery, and cleans up its temporary data. The key can stay connected throughout.

## Prepare a release

The packaging script runs on Linux, requires a new output directory, and builds Linux and macOS archives for amd64 and arm64. To rehearse locally, use a disposable directory and a test version:

```sh
scratch=$(mktemp -d)
./scripts/package-release.sh v0.0.0 "$scratch/assets"
sh install.sh --from-dir "$scratch/assets" "$scratch/bin"
"$scratch/bin/kubeconfig-vault" --version
```

Two Linux runners build the same revision with the same Go toolchain and locked Node dependencies. The second runner compiles with a fresh Go build cache and a different file-creation mask. The packager fixes file modes, member order, ownership, timestamps, and gzip headers so another build can produce the same four archives. CI compares both checksum manifests and checks every archive and the installer against the second build. To repeat the comparison locally, use two clean checkouts of the same commit and tag, build on Linux with the release toolchain, and compare the two `SHA256SUMS` files. [Archive metadata and reproducible builds](https://reproducible-builds.org/docs/archives/)

Changes to the packaging script or release workflow rehearse these checks in pull requests. You can also run the Release workflow manually. Rehearsals use the version `v0.0.0` and create temporary workflow artifacts.

For a real release, pushing a `vMAJOR.MINOR.PATCH` tag starts the release workflow. It runs CI, builds the four archives, installs each on its target platform, and checks the checksum manifest. Each installed CLI must pass the token and mutual-TLS preflights and the virtual-authenticator browser suite with real kubectl before the workflow attests the artifacts and creates a draft. Review the tag, notes, and all six assets before publishing. [Release workflow](../.github/workflows/release.yml)

On publication, four native runners download the installer and their matching archive anonymously. Each verifies release provenance, installs in a temporary home, and checks the binary bytes, version, and compatibility link. The check tries the immutable tag first and the README’s latest URL while that tag is current. For tagged installers from v0.3.1 onward, use the workflow’s manual tag input to repeat the check. A hosted macOS install does not exercise Finder quarantine or first launch on a user's Mac. [Public installation workflow](../.github/workflows/public-install.yml)

To verify a downloaded archive against its build attestation, run `gh attestation verify kubeconfig-vault-linux-amd64.tar.gz --repo mojish/kubeconfig-vault`. To install downloaded assets offline, place the matching archive and `SHA256SUMS` in one directory and run `sh install.sh --from-dir DIRECTORY` using the published installer.
