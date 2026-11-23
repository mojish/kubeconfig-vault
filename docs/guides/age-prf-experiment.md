# Age/PRF library experiment

This is a library interoperability test, separate from the application.

## Running it


This is separate from the installed helper. It needs Go 1.25+, Node.js 22.12+,
and Google Chrome. Run these commands from `experiments/age-prf`:

```sh
export GOPATH="${TMPDIR:-/tmp}/kube-unlock-go-path"
export GOCACHE="${TMPDIR:-/tmp}/kube-unlock-go-cache"
npm ci --ignore-scripts --no-audit --no-fund
go mod download
npm test
```

Set `GOPATH` and `GOCACHE` to the same locations for download and test. If unset,
the harness uses `kube-unlock-go-path` and `kube-unlock-go-cache` below the OS
temporary directory. The test compiles with network dependency fetching disabled.
Set `KUBE_UNLOCK_TEST_CHROME` to override the browser executable. Defaults are
`google-chrome` on Linux and the Google Chrome application path on macOS.

The harness runs only synthetic data and virtual authenticators, then removes
its disposable profile and executable. It prints boolean test outcomes, never
keys or payloads. A successful Linux run does not certify macOS or a physical
YubiKey. The design and limits below define its scope.

## Design and limits


`experiments/age-prf` qualifies the selected age/Typage WebAuthn backend using a
fixed synthetic payload, virtual authenticators, and a disposable browser profile.
It never opens the existing helper state, kubeconfig, or real browser profile.
Its native driver accepts no file paths and has no network listener.

The test starts a Go age driver over private stdio and serves locally bundled
Typage assets on loopback. Chrome creates a non-discoverable virtual credential.
For encryption, age generates a fresh file key. The test harness sends that key
to Typage's WebAuthn recipient and returns the resulting standard recipient stanza
to age. Payload encryption and decryption stay in Go. For decryption, Typage
unwraps the file key and age verifies the header and payload before the driver
reports whether the complete dummy payload matched. No plaintext is returned.

Every file also has a hybrid age recovery recipient. Its synthetic private key
exists only in the test process. The browser sees neither this private key nor
the payload. Recovery is tested with all virtual authenticators removed. The
selected product recovery model is a daily YubiKey plus an independently stored
offline recovery key. An offline recovery key can decrypt without the YubiKey.
The experiment itself does not implement recovery-key creation or export.
Those workflows are implemented in the [age application](../ARCHITECTURE.md#age-application).

The browser/native bridge currently uses the test harness's DevTools connection.
There is no production HTTP key-transfer protocol in this experiment. The small
static server serves public assets only and is not an unlock service.

The assertions cover a new browser document, empty browser storage, independent
file keys, corrupted ciphertext, unrelated recovery keys, a different virtual
authenticator, and lack of PRF support. A failure stops the test and cleanup
removes its temporary files and browser profile. Passing is evidence of library
interoperability with Chrome's emulation, not physical-key, macOS runtime,
Freelens, or production session-security verification.

Source versions are pinned in the experiment's npm and Go lockfiles. Upstream
Typage still marks its WebAuthn API experimental. No runtime CDN is used.
References: [Typage](https://github.com/FiloSottile/typage/tree/v0.3.1),
[age file format](https://c2sp.org/age).
