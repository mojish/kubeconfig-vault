# Historical Python prototype

This preserves the earlier Linux-only implementation and its workflows.
For new evaluation, start with the Go/Typage application in the [README](../README.md).
The root `./kube-unlock` launcher still runs this prototype; it does not invoke the
age application. The two vault formats and state directories are incompatible.

## Prerequisites

Linux, Python 3.12, and the system packages `python3-fido2`,
`python3-cryptography`, and `python3-yaml`. Tests additionally use Node.js 22,
Chrome, kubectl, and optionally Freelens 2.1.0.
The UI test uses Bubblewrap to hide the real home directory.

A browser that passes the PRF probe and a USB FIDO2 security key are required.
Browser launch uses `xdg-open`. Configure a compatible default browser.

## Setup

Run from the project directory. The launcher resolves symlinks to its source.
Keep the project in place after generating connection configurations.

```sh
./kube-unlock --help
./kube-unlock probe
```

Use the printed localhost address for the probe. It uses a separate test
credential and dummy message. Stop it with Ctrl+C when finished.

## Build and test

```sh
python3 -m unittest discover -s tests -v
node tests/crypto.test.mjs
node tests/browser.mjs
node tests/vault_browser.mjs
node tests/vault_browser.mjs --freelens-ui
```

The tests bind localhost sockets and launch isolated browser profiles.
The vault integration uses a synthetic HTTPS API and explicit temporary
kubeconfigs. It never uses the developer's stored Kubernetes credentials.
It also tests the proxy bundled in Freelens. The optional UI test runs the
installed application with a temporary profile inside a filesystem namespace.
Its UI scope is discovery, cold browser unlock, and authenticated namespace
requests. It scans the isolated profile/logs for the synthetic token. It does not
exercise terminal/log views or connect to a real cluster.

## Lint and format

```sh
python3 -m compileall -q kube_unlock.py probe.py runtime.py vault_core.py tests
node --check web/vault.js
```

## User-operated migration

Run import yourself. It reads only the explicitly selected configuration and
its supported references. No assistant process should execute this step.

```sh
./kube-unlock import "$HOME/.kube/config"
```

Register the physical key in the browser, then complete the encryption step.
The original file remains unchanged. Verify the generated candidate with:

```sh
./kube-unlock lock
kubectl --kubeconfig="$HOME/.local/share/kube-unlock/current/kubeconfig" get namespaces
```

This command uses your existing credential and contacts your selected cluster.
Use a permitted read operation if listing namespaces is not allowed.
For several source files, import the selected file only. This release does not
merge other entries from `KUBECONFIG` or switch your clients automatically.

After verification, select the generated file through `KUBECONFIG` or
`--kubeconfig`. In Freelens, add that same file under its synchronized kubeconfig
settings. Keep a file reference rather than pasting a copy, so later saves apply.
Close and reconnect existing client sessions when changing credentials.

Enroll a backup key with `./kube-unlock key add` and test it before relying on the
vault as the only copy. Original files, token files, editor backups, and snapshots
remain alternative access paths until you deliberately remove or protect them.
Review those copies yourself after candidate and recovery verification.
Rollback is selecting your original file again. Import never deletes it.

## Editing

```sh
./kube-unlock config unlock
# Open the printed path in your normal editor, make changes, and save.
./kube-unlock config lock
```

Alternatively, `./kube-unlock edit` launches `VISUAL`, `EDITOR`, or `vi` and waits.
Configure graphical editors with their wait option. Do not save unrelated copies.
Disable editor swap, backup, autosave, and extensions that retain plaintext.

If validation fails, the editable copy remains. `./kube-unlock status` shows its
path. Correct it and repeat the lock command. Changes to connection/trust fields
require `config lock --accept-connection-changes` after your local review.
`config discard` deliberately deletes the current edit without saving.

Relative CA and token-file paths resolve against the original source directory.
An imported token-file value is snapshotted. To change it later, replace the
reference with an inline token, or explicitly select a different token-file path.

## Session and recovery

`lock` clears the helper session. `stop` also exits its background process.
Both preserve unfinished edits. `unlock` requests fresh authentication.
The default session is one hour. `--session-seconds` affects a newly started
daemon, so stop the previous daemon before selecting a different duration.

`backups` lists generation identifiers. `restore ID` decrypts a selected backup
and saves it as a new generation. Save or discard an edit before restoring.
`export PATH` writes an unlocked plaintext copy to a new file and never overwrites
an existing path. `config repair` regenerates a manually damaged connection file.
Export preserves file references rather than flattening them into a portable file.
Recovery from losing every enrolled key requires an independently protected copy.


## Contract

Use the launcher help for exact argument syntax.

| Command | Result |
| --- | --- |
| `probe` | Temporary hardware compatibility check using dummy data |
| `import SOURCE` | Encrypted vault plus candidate connection file, original unchanged |
| `status` | Session state, pending-edit path, and enrolled-key count |
| `unlock` | Fresh authentication and a new absolute session deadline |
| `lock` / `stop` | Clear cache / clear cache and stop daemon, preserving edits |
| `config unlock` | Print the private editable source path |
| `config lock` | Validate, encrypt, regenerate, remove edit, and clear session |
| `edit` | Normal editor convenience workflow |
| `config discard` | Remove an unfinished edit without saving, available while locked |
| `config repair` | Regenerate connection data from the encrypted source |
| `key add` | Authenticate the existing key, then enroll another key |
| `backups` / `restore ID` | List generation identifiers / restore into a new generation |
| `export PATH` | Write a plaintext export to a new mode-0600 file |
| `credential ID` | Internal Kubernetes exec protocol entry point |

The default state directory is `~/.local/share/kube-unlock`. Override it with
`--state-dir`. State directories must be owned by the user with mode 0700.
`--session-seconds` accepts 30 through 86400 and defaults to 3600. A running
daemon retains the duration it started with. `XDG_RUNTIME_DIR` must be available.

Import supports one UTF-8 Kubernetes v1 Config at a time, up to 4 MiB. It requires
token-only users and valid named cluster/user/context references. Inline token
values remain unchanged. `--allow-token-files` explicitly permits initial
token-file reads. Existing snapshots are reused on ordinary edits.
No `KUBECONFIG` merge is inferred. Exec, auth-provider, client-certificate,
private-key, and unknown cluster/context fields are rejected before migration.
No imported command is executed. Server URLs must use HTTPS without embedded
credentials, query, or fragment. Public CA paths are resolved at import/save and
embedded in the generated file. Duplicate mapping keys and named entries fail.

The connection file is `STATE/current/kubeconfig`. Clients may change its
current-context and namespace selections. Other manual mutations are detected
before credential release. Change the encrypted source instead.
Connection/trust edits require `config lock --accept-connection-changes`.

The generated exec command has an absolute interpreter and script path,
`client.authentication.k8s.io/v1`, `interactiveMode: Never`, and
`provideClusterInfo: true`. Never means no terminal stdin, not no browser UI.
Credential stdout contains only ExecCredential JSON. Errors use stderr and a
nonzero exit status. No token digest or real source excerpt is logged.

## Backward-compatibility rules

Persistent vault format version 1 is checked before decryption. Unsupported
versions fail. The CLI and generated projection are local interfaces, not a
published package API. Keep the source path stable while a projection refers to
it. Existing Kubernetes tokens and their server-side semantics are unchanged.

The lifecycle and security limits are defined in
[architecture](#protection-boundaries).



## Components

This section describes only the historical Python helper.

- CLI: explicit import/edit/export commands and Kubernetes exec responses.
- Session process: one process per state directory, protected by a file lock.
- Private Unix socket: commands and token delivery, checked against the peer UID.
- Loopback HTTP server: local browser assets and WebAuthn ceremonies.
- Storage: encrypted generations and a generated, token-free connection file.

## System context

All added components run locally. Kubernetes continues to validate the original
bearer token. The system does not rotate it, extend its lifetime, change RBAC,
or create a cluster identity service. Freelens uses its Kubernetes proxy to invoke
the same helper that kubectl invokes.

## Key invariants

The full source text and token records are encrypted with a random AES-256-GCM
data key. Each enrolled security key wraps that data key using WebAuthn PRF,
HKDF-SHA256 with purpose separation, and AES-256-GCM. PRF outputs and wrapping
keys stay in the browser. The unwrapped data key is delivered to the local
session process after a verified assertion. No token is sent to browser code.

Persistent generations contain ciphertext, public authentication metadata,
wrapped data keys, and the generated client configuration. The latter exposes
cluster/context names, server addresses, and public trust material, but no raw
managed token. Source comments and unknown top-level fields remain encrypted.

Each save writes both generation files, syncs them, and atomically replaces the
current-generation symlink. Failures before the replacement preserve the old
pair. Normally the current generation plus three older directories remain.
Cleanup failure can leave additional encrypted generations. Uncommitted staging
directories may also remain after a failed write.

## Primary flow

1. A client invokes the generated exec command with its selected cluster data.
2. The helper contacts or starts the private session process.
3. A valid cached session serves the credential without browser interaction.
4. Otherwise concurrent requests join one unlock attempt. A localhost page opens.
5. The browser requires user presence and verification with a selected USB key.
   Fresh challenges, RP ID, exact origin, and the assertion signature are checked.
6. The browser unwraps the data key. The process decrypts the source and checks
   the credential ID, destination, and TLS trust against the approved projection.
7. A successful exec response contains the original token and an expiry no later
   than the absolute session deadline or a known token expiry.

Retrieval does not extend the deadline. The Linux session clock includes suspend
time, so sleeping the laptop does not extend the session. Expiry or restart discards the cached
key and payload. Browser cancellation or a five-minute unlock timeout fails
waiting requests. A 30-second cooldown prevents repeated background tab launches.
An explicit unlock permits an immediate retry. Each WebAuthn step expires after
two minutes. A later attempt cannot reuse a consumed challenge.

The browser receives a short-lived launch capability in the URL fragment and
immediately clears it from the address bar. It sends it only in request headers.
This capability is not a Kubernetes token or encryption key. HTTP checks exact
Host and Origin, rejects cross-site requests, and uses bounded JSON bodies.
Assets are local, CSP disallows external scripts and framing, and responses are
not cached. No localStorage/sessionStorage is used.

## Editing and failure recovery

Unlocking an edit creates a mode-0600 source copy below a private directory in
`XDG_RUNTIME_DIR`, normally tmpfs on this Linux desktop. One edit is allowed at a
time. Save validates the source and checks its original generation before
committing. Invalid YAML and concurrent generation changes retain the edit.
Connection/trust changes require explicit local acceptance. Source changes do
not silently overwrite current-context or namespace selections made by clients.

A successful save clears the session before deleting the edit copy. A cleanup
failure cannot leave an older credential cached. A crash preserves any existing
edit until explicit save or discard. Reboot/logout may erase the runtime directory
and unsaved edits. State never promises persistence for unsaved text.

## Protection boundaries

This protects stored credentials and gates acquisition on a trusted laptop.
It is not server-enforced MFA for the existing bearer token. Locking cannot revoke
tokens already handed to clients or terminate their established streams.
An expired or revoked token still fails after successful YubiKey authentication.

Arbitrary code running as this user, a hostile browser extension, or root can
misuse an unlocked session. Same-UID processes can use the private IPC socket.
Python/browser allocations cannot guarantee complete memory erasure. Core dumps
are disabled in CLI processes, but swap and hibernation remain OS concerns.
Editor artifacts and original credential copies are outside vault protection.

No authenticator manufacturer attestation is enforced. Select the intended USB
YubiKey. The code requires verification and presence and does not downgrade to
plaintext when PRF is unavailable.

References: [Kubernetes exec plugins](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins),
[Yubico PRF guidance](https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/Developers_Guide_to_PRF.html).
