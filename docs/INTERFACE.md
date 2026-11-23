# CLI reference

The general form is `kubeconfig-vault [global options] COMMAND`. Put global options before the command. For a first installation, start with `setup`. Use `help COMMAND` or `COMMAND --help` for focused guidance. For a worked example of editing or recovery, see the [user guide](README.md).

## Setup and client files

| Command | Effect |
| --- | --- |
| `setup [FILE]` | Validate one source, enroll the key if needed, save an encrypted rollback, and link the client path. Safe to repeat after an interrupted setup. |
| `setup --check [FILE]` | Validate the input format locally. Reads the selected file and any referenced public CA. Leaves the filesystem untouched and skips browser enrollment and API connectivity checks. |
| `import [SOURCE]` | Create a vault from a source file and leave the source in place. Defaults to `~/.kube/config`. The original still contains the original credentials. |
| `import SOURCE --recovery-key FILE` | Import using a private recovery key you already hold. Useful without a controlling terminal. |
| `config link [--kubeconfig FILE]` | Attach a client path to an existing vault. An existing supported source gets an encrypted rollback. A previously empty path gets a receipt recording that fact. |
| `config unlink [--kubeconfig FILE]` | Restore the original at that path, or detach a link whose path was originally empty. |
| `config repair [--kubeconfig FILE]` | Authenticate and rebuild a missing generated kubeconfig for an already linked client. |

`setup`, `config link`, `config unlink` and `config repair` use the single file selected by `KUBECONFIG`, or `~/.kube/config` by default. If `KUBECONFIG` lists multiple files, select one explicitly. Existing aliases to a source follow the link at its resolved target. Setup prints the target before replacing it. Relative CA paths resolve against the selected client path.

Setup and link store the encrypted original next to its target as `FILE.before-kubeconfig-vault.age`. A private receipt binds the target path to that backup’s digest. Keep both until unlink completes. After an interrupted setup, keep the original and rollback in place and repeat setup. A stale client-go `.lock` file can survive a killed writer. Confirm that every Vault and kubectl writer for that file has exited before removing the stale lock.

## Sessions and editing

| Command | Effect |
| --- | --- |
| `status [--json]` | Inspect the helper, active generation, and known plaintext edit paths. Works while the helper is stopped. |
| `unlock` | Authenticate now and start a new credential session, including during an automatic prompt pause. |
| `lock` / `stop` | Cancel pending authentication and clear the cached session. `stop` also exits the helper. Both preserve open edits. |
| `edit` (also `config edit`) | Open a private edit in your editor and attempt to verify and encrypt it when the editor exits successfully. |
| `config unlock` | Authenticate and create a plaintext file for editing separately. |
| `config lock [--accept-connection-changes]` | Validate and save the edit, verify the new vault, and remove the plaintext. The flag approves reviewed changes to connection, trust, or user mapping. |
| `config discard` | Delete the unsaved edit and any interrupted-save copy, and clear the session. |
| `path kubeconfig` / `path edit` / `path vault` | Print the path of the requested existing file. `status` lists interrupted-save paths. |

The editor comes from `VISUAL`, then `EDITOR`, then `vi`. An executable path can contain spaces. When specifying arguments, separate them with whitespace. The helper adds `--wait` to supported GUI editors. An unsuccessful editor exit preserves the edit. `config lock` reports `changed: false` if the authenticated original and current inputs still match, or `changed: true` after publishing a new save.

## Backups and recovery

| Command | Output or result |
| --- | --- |
| `backup NEW-FILE` | A copy of the current encrypted generation. Can succeed even if the generated client file is damaged. |
| `recover VAULT.age [--key FILE] --check` | Verify an encrypted backup and the offline key in memory. |
| `recover VAULT.age [--key FILE] --out NEW-FILE` | Decrypt a trusted backup into a new portable plaintext kubeconfig. |
| `restore VAULT.age [--key FILE]` | In an unused state directory, enroll a security key using the trusted backup and its offline key. |
| `export NEW-FILE` | Authenticate with the security key and export the latest portable plaintext config. |
| `history prune --keep COUNT` | Authenticate and retain the active generation plus the newest others, up to the requested count. An open edit blocks pruning. Separate backups and rollback copies are preserved. |
| `recovery-key new FILE` / `recovery-key public FILE` | Create a private hybrid age key file, or print its public recipient. Normal setup generates a recovery key for you. |

For `recover` and `restore`, omitting `--key FILE` opens a hidden terminal prompt. File-based recovery identities must belong to you, have private permissions and have no hard links. Backup, recovery and export require unused output filenames. Portable exports embed public CAs and can differ from the original formatting.

## Status and repair

On a terminal, `status` prints a human-readable result. A pipe or `--json` selects JSON. A healthy inspection exits with code 0, including before setup. An unsafe path, incomplete generation or unavailable helper produces a degraded report and exits with code 1.

| JSON field | Meaning |
| --- | --- |
| `configured`, `helper_running`, `unlocked` | Whether the expected generation files are present and pass metadata checks, a helper answered, and a credential session is open, respectively. |
| `expires_at`, `automatic_unlock_paused_until` | UTC deadlines when a session is active or automatic prompting is paused. |
| `edit_open`, `edit_path`, `edit_paths` | Known plaintext edits, including an interrupted save. Preserve wanted changes before discarding. |
| `fully_locked` | False for an open session, a detected plaintext edit, or uncertainty during inspection. |
| `problems`, `next_action` | The observed failures and a suggested next step on a degraded vault. |

Repair requires an already linked client, a missing generated file, readable encrypted state, and no open edit. It authenticates with the security key and rechecks the selected link and generation before publishing. It refuses to overwrite an existing entry. [Recovery options](README.md#choose-a-recovery-path)

## Supported kubeconfig inputs

- **File** — one Kubernetes `v1` `Config` document, up to 4 MiB. The generated and portable versions must also fit after CAs are embedded.
- **Authentication** — one inline `token` **or** both `client-certificate-data` and `client-key-data` per user. Different users in one file can use different methods. Certificate inputs must be complete base64-encoded PEM, with an end-user certificate first and a matching unencrypted private key. CA signing keys and certificates restricted to server use are rejected. The helper checks the leaf validity period when serving a credential. File-based user credentials, username/password, exec plugins, and auth providers are unsupported.
- **TLS and proxies** — verified HTTPS with system trust or a public CA certificate supplied inline or by file. CA inputs must contain public certificate PEM blocks only. Supported proxy schemes are HTTP, HTTPS and SOCKS5. The proxy address is copied into the readable client file, so credentials, query strings and fragments are rejected.
- **Contexts** — named clusters, users and contexts with valid references. Clients can update the current context and namespace. The encrypted editable source preserves legacy `preferences`. The generated client file and portable export omit them.
- **Paths and fields** — standalone import expects a regular source file. Setup can handle an existing source symlink. CA and recovery-key file inputs reject symlinks. Unknown fields and extensions outside `preferences` fail validation.

## Global options and client integration

| Option | Meaning |
| --- | --- |
| `--version` | Print the packaged release version. Source builds normally report `dev`. |
| `--state-dir PATH` | Choose a private state directory. Defaults to `~/.local/share/kube-unlock-age` on Linux or `~/Library/Application Support/kube-unlock-age` on macOS. Long paths can exceed the OS Unix socket limit. |
| `--session-seconds N` | Set the absolute session lifetime for a new helper. Range 1–3600. Default 3600. |
| `--browser PATH` | Choose a browser launcher executable with no arguments. Defaults to `xdg-open` on Linux and `open` on macOS. The launcher must accept a private local HTML file and follow its redirect to localhost. |

Stop a running helper before changing its browser or session settings. `serve` runs the helper in the foreground for diagnostics.

Kubernetes clients invoke `credential ID` through the generated exec configuration. It uses an absolute executable path, `client.authentication.k8s.io/v1`, `interactiveMode: Never`, and `provideClusterInfo: true`. The helper checks the requested cluster against the approved binding before returning an `ExecCredential`. Named entry order and an absent, null or empty exec environment are equivalent. Changed commands, argument order, nonempty exec environments and per-cluster exec extensions fail validation. [Credential flow](ARCHITECTURE.md#one-kubernetes-request)
