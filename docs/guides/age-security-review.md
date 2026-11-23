# Age application security review

## Status and scope

The 2026-11-23 implementation review reproduced four issues. Remediation adds
regression-tested fixes and updates the build baseline to Go 1.26.11. The supported
edit workflow requires closing the editor before locking. The updated Linux
hardware flow passed with the key left connected. macOS runtime testing and
independent review remain outstanding, as described below.

This work was performed by the assistant that developed the application. It is
not an independent audit or certification of age, Typage, WebAuthn, or Go. Scope
covers `age-app` native operations, IPC, browser handoff, sessions, configuration
projection, generation storage, and dependencies. The workspace graph had no
indexed coverage for this component. Claims were checked against source and tests.

Tests use dummy credentials, temporary state, fake browser adapters or virtual
authenticators, and loopback endpoints. Real kubeconfigs, vaults, recovery keys,
SSH secrets, and Freelens profiles were not accessed. The existing Python helper
was unchanged. No production request or credential migration occurred.

## Findings and disposition

| ID | Severity | Remediation | Regression evidence |
| --- | --- | --- | --- |
| R1 | Medium | Strict certificate parsing | Mixed PEM, private keys, headers, malformed blocks, and unrelated data rejected for inline and file inputs |
| R2 | Medium | Edit comparison and isolated finalization | Completed writes during authentication preserved, late replacements retained, interrupted edits visible |
| R3 | Low | Serialized-size checks and candidate read-back | Oversized expansion rejected, invalid candidates leave current unchanged |
| R4 | Medium, conditional | Private bootstrap replaces capability in launch arguments | No capability in arguments, private file modes checked, launch URI cannot authorize API access |
| R5 | Build prerequisite | Go 1.26.11 minimum and rebuilt artifacts | Regression/integration tests pass, current symbol scan is clean |

### R1: CA material in the unencrypted projection

Originally, `prepare` accepted a certificate followed by a private key because
[`AppendCertsFromPEM`](https://pkg.go.dev/crypto/x509#CertPool.AppendCertsFromPEM)
requires only that some certificates parse. The synthetic combined PEM file
survived commit with its private-key block in the unencrypted generated config.
Restrictive file permissions did not encrypt that copy.

[`publicCertificates`](../../age-app/config.go) now parses exact certificate
blocks, rejects unrelated material and PEM headers, and re-encodes certificates.
Tests cover both input forms and malformed content before a later valid block.
The change governs new imports and saves. It does not inspect or rewrite existing
states or remove previously created plaintext copies.

### R2: Edits changed during save

Originally, a write completed while save waited for authentication could be
deleted after an older in-memory snapshot was committed. A synthetic end-to-end
save reproduced this without a hostile process.

[`saveEdit`](../../age-app/service.go) and
[`finalizeEdit`](../../age-app/store.go) now isolate the file being finalized,
compare its contents before commit, and check it again afterward. Tests verify
that completed in-place writes and atomic replacements during authentication
abort commit and preserve newer text. A replacement created during final commit
is retained. Commit errors retain the edit. Interrupted plaintext is reported
and blocks a new edit/save until resolved.

**Boundary:** this is not a general concurrent-editor protocol. Another process
that retains an open writable descriptor can still race the final check and
cleanup. The tested open-handle case writes during commit, before the last check.
It does not establish safety for every later write. Close the editor before
locking. Recovery and status behavior are defined in
[architecture](../ARCHITECTURE.md#age-editing-and-limitations) and
[the editing workflow](../DEVELOPMENT.md#age-user-operated-workflow).

### R3: Unreadable committed configuration

The original implementation accepted a roughly 3.25 MiB certificate-only CA file.
Base64 expansion produced a roughly 4.33 MiB connection file, exceeding the
4 MiB reader limit. Native age verification and commit succeeded, then normal
loading failed. The ciphertext remained recoverable through the offline key.

[`serializeConfig`](../../age-app/config.go) now checks generated and portable
configurations before acceptance. [`commitSnapshot`](../../age-app/store.go)
also checks serialized artifacts and reloads the candidate through the normal
generation reader before switching `current`. Regression cases cover expansion,
projection/portable size, metadata size, and invalid metadata. Rejected commits
leave the previous generation readable.

### R4: Capability exposed through process arguments

The original browser command contained a bearer capability in the URL fragment.
A Linux probe extracted it from its own fake launcher's arguments and polled a
pending dummy encryption file key. A second OS user was not exercised. Cross-user
risk depended on process visibility, timing, and later access to the ciphertext.
Linux documents visibility controls under
[procfs mount options](https://docs.kernel.org/filesystems/proc.html#mount-options).

[`newCeremony`](../../age-app/browser.go) now passes only a private file URI to
the launcher. The browser reads the capability from a private file under the
user's filesystem permissions. Tests inspect the fake launcher's arguments and
file/directory modes. Supplying the visible launch URI as an API capability is
rejected. Reading the private file as the same user permits the intended handoff.
Cleanup is tested on handoff, launch failure, and cancellation.

Chrome integration follows the actual file redirect. It exposed a navigation
rejection, corrected by allowing only cross-site top-level navigation to the
public landing page. Dedicated tests still reject cross-site API calls, including
ones with a valid capability, and cross-site frames or subresources. Same-UID
malware, root, and browser compromise remain outside the threat model. Full
second-UID exploitation and macOS launch behavior remain unverified. See
[the bridge lifecycle](../ARCHITECTURE.md#age-application).

### R5: Build baseline and dependency scan

The original Go 1.25.8 source scan with `govulncheck` v1.10.0 reported 44 unique
advisory IDs, including 19 with standard-library symbol traces. These were static
matches, not demonstrated exploits. Several had runtime or platform preconditions
absent from this application.

With the same dependencies and Go 1.26.11, there were zero symbol-level or
imported-package findings. Three module-only matches remained in unused
OpenPGP/SSH packages: GO-2026-5932, GO-2026-6354, and GO-2026-6355.
`go list -deps` confirmed those packages were not imported. See
[Go vulnerability analysis](https://go.dev/doc/security/vuln/) for these distinctions.

The module now requires Go 1.26.11. The Linux binary was rebuilt and its metadata
confirmed that version. The repeatable `audit:security` command reported zero npm
advisories and zero called/imported-package Go findings, with the same three
module-only matches. Keep builds patched under
[Go's release policy](https://go.dev/doc/devel/release). Advisory scans do not
assess the application's protocol or prove exploit absence.

A later CI-preparation recheck on 2026-11-23 still reported zero npm advisories,
but Go's public database returned HTTP 403 twice. That recheck is blocked, not
clean; the earlier successful Go scan is historical evidence. The CI command
continues to fail on database errors rather than suppressing them.

## Validation and remaining qualification

Completed with synthetic data on Linux:

- Go regression suite with the race detector and `go vet`.
- Three delayed-response UI tests.
- Isolated Chrome with virtual FIDO2, native age, real kubectl to a dummy HTTPS
  API, and Freelens's installed Kubernetes proxy with an explicit synthetic config.
  Coverage includes cold/concurrent/warm access, session reuse, editing,
  cancellation, expiry, export, and offline recovery.
- Browser requests and persistent generations checked for dummy token/recovery
  material. No external browser assets were used.
- Rebuilt Linux executable and cross-builds for macOS arm64/amd64.
- Repeatable dependency scan and documentation structure checks.

The old bug-confirming overlay probes were replaced by normal
[regression tests](../../age-app/review_regression_test.go). Passing now requires
the corrected behavior within the stated scope. Commands are in
[development](../DEVELOPMENT.md#security-regression-tests).

The updated [physical-key check](../DEVELOPMENT.md#physical-yubikey-qualification)
completed enrollment, native verification, cold kubectl unlock, cached access,
and offline recovery with a user-operated USB YubiKey in isolated Chrome. It ran
with the key connected throughout and explicitly skipped the removal check.
The helper remained locked during recovery, no additional browser opened, and
the recovered config worked against the dummy API. Cleanup completed successfully.

macOS runtime, full Freelens GUI behavior for this backend, and independent
security review remain outstanding. Cross-builds and virtual authenticators do
not establish those results. The connected-key run does not prove key-absence
behavior and must not be described as a physical-removal test.

The prepared [CI workflow](continuous-integration.md) adds native Go tests for
both macOS architectures without requiring a contributor-owned Mac. A new native
socket test checks same-user peer lookup in both directions and rejection after
socket closure. It passed on Linux; it does not simulate a different OS user.
Check the [hosted macOS jobs](https://github.com/mojish/kubeconfig-vault/actions/workflows/ci.yml)
for current native results. Desktop browser launch and physical-key testing on
macOS remain separate checks.
