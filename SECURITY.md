# Security

Report suspected vulnerabilities through [GitHub private vulnerability reporting](https://github.com/mojish/kubeconfig-vault/security/advisories/new).
Include the release version, operating system, and a description using synthetic
data. Keep kubeconfigs, client private keys, tokens, recovery identities, PINs and browser session
URLs private. See the [security boundaries](docs/ARCHITECTURE.md) for the local
threat model and the limitations of client-side locking.

## Independent review before v1

The project is experimental. An independent security assessment is pending.
Use the tagged release under review, its source commit, and synthetic data.
The [disposable trial kit](docs/TRIALS.md) pins the application and test scripts and provides a loopback API for editing and recovery. Review the application and release workflow at the binary’s source commit. Record the test-source commit separately so a later harness can exercise an earlier binary.
Include the following areas in the assessment.

| Boundary | What to verify | Source and existing checks |
| --- | --- | --- |
| Browser and local helper | Only the active ceremony can use a step. Cancellation, origin checks and timeouts close access. Kubernetes credentials and recovery identities stay out of the browser. | `age-app/browser.go`, `web/app.mjs` under `age-app`, `browser.test.mjs` |
| Authenticated storage | Both recipients recover the enrolled payload. Modified ciphertext, substituted settings and incomplete writes preserve the previous usable vault. | `age-app/store.go`, `service.go`, `setup.go`, `setup_test.go` |
| Client and daemon | Peer identity, cluster/TLS binding and expiration hold under concurrent requests, explicit lock, cancellation and restart. A client holding a delivered Kubernetes credential is a separate trust boundary. | `age-app/main.go`, `peer_linux.go`, `peer_darwin.go`, `service.go` |
| Embedded TLS credentials | Verify certificate/key matching, client usage and expiry at delivery. Check that the generated client file, browser requests and errors exclude private key material. The requesting native client receives the key. | [Certificate validation](age-app/client_certificate.go), [mixed-authentication integration](age-app/browser.test.mjs) |
| Lost-key recovery | Back up before and after a disposable edit. Compare each backup with the current encrypted generation and verify that the offline key still decrypts both. Use the edited backup for an authenticated API read, then unlink and compare with the exact original. | [Recovery guide](docs/README.md#choose-a-recovery-path), [test protocol](docs/COMPATIBILITY.md#most-valuable-next-trials) |
| Plaintext editing | Unchanged saves check authenticated state and resolved CA data. Changed/failed saves, concurrent replacements and interrupted cleanup preserve user data and report every open edit. | `age-app/service.go`, `store.go`, `editor.go` |
| Distribution | Release workflow permissions, pinned tools, attestations, checksums and upgrade aliases match the packages users install. | [Release workflow](.github/workflows/release.yml), [installer](install.sh) |

Record the commit, platforms, areas reviewed, limitations, and remediation
retest results in the assessment. Report vulnerabilities privately using the link
above. Publish a redacted assessment and its reviewed commit after remediation.
For a candidate that changes client compatibility or recovery, also check that
kubectl rewrites preserve the authenticated cluster and user bindings, an
unexpected unlock can be declined while a second client waits, and an offline
backup survives loss of the generated kubeconfig. Review the migration path for
older proxy URLs and verify that installer downloads come from a single release.
The automated suite and [desktop hardware protocol](docs/MACOS.md) provide
reproducible checks for a reviewer. Each has a different scope from a human
security assessment.
