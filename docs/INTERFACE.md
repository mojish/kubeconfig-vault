# CLI and kubeconfig reference

## Options

`--version` prints the packaged release version. Source builds report `dev`.

The installed command is `kubeconfig-vault`. The installer also provides
`kube-unlock-age` for existing kubeconfigs. On the next verified edit, the helper
updates the embedded command when the old path is the installer-created alias.

State directories remain `~/.local/share/kube-unlock-age` on Linux and
`~/Library/Application Support/kube-unlock-age` on macOS. `--state-dir` selects a
private directory; Unix socket limits also constrain its path length.
`--session-seconds` accepts 1–3600, default 3600, and affects only a new daemon.
`--browser` selects one executable without shell arguments; otherwise Linux uses
`xdg-open`, macOS `open`. Stop the daemon before changing these settings.
The executable receives a private HTML `file:` URI. It must open local HTML files
and follow their redirect to localhost. No launch capability appears in arguments.

## Commands

| Command | Result |
| --- | --- |
| `recovery-key new FILE` | Exclusive private hybrid age identity file; no secret stdout |
| `recovery-key public FILE` | Public recipient only |
| `setup [FILE]` | Enroll if needed, verify encrypted rollback and attach a single client file |
| `backup NEW-FILE` | Copy the current ciphertext for portable offline recovery |
| `recover VAULT.age [--key FILE] --check` | Verify recovery and config validation in memory |
| `restore VAULT.age [--key FILE]` | Restore into an unused state directory with fresh security-key enrollment and the same recovery key |
| `history prune --keep COUNT` | Fresh authentication, then retain the active and newest generations, COUNT total |
| `config edit` | Run the configured foreground editor, then encrypt and verify changes |
| `import [SOURCE]` | Import from `~/.kube/config` by default, confirm recovery backup, then enroll and verify the vault |
| `import SOURCE --recovery-key FILE` | Enroll and verify the vault using an existing private key file |
| `path kubeconfig` / `path edit` / `path vault` | Print only the absolute path to the selected file |
| `status [--json]` | Passive status, including `configured` and `helper_running`. Human-readable session state on a terminal, JSON when piped or requested. JSON includes session state, expiry, primary `edit_path`, all `edit_paths`, and `fully_locked` |
| `unlock` | Fresh browser authentication and an absolute credential session |
| `lock` / `stop` | Cancel authentication and clear cache; stop also exits daemon |
| `config unlock` | Fresh authentication and a plaintext edit file |
| `config lock [--accept-connection-changes]` | Validate, encrypt, verify, commit, delete edit |
| `config discard` | Delete normal and interrupted-save edits and clear cache |
| `config link [--kubeconfig FILE]` | Link the default config or a selected file to the generated client config |
| `config repair [--kubeconfig FILE]` | Authenticate and restore a missing generated config for an already linked client |
| `config unlink [--kubeconfig FILE]` | Restore the backed-up entry, or remove the managed link if it had no original |
| `export NEW-FILE` | Fresh authentication and portable plaintext export |
| `recover VAULT.age --out NEW-FILE` | Offline recovery. Paste the key at a hidden terminal prompt. |
| `recover VAULT.age --key FILE --out NEW-FILE` | Offline recovery using an existing private key file |
| `credential ID` | ExecCredential v1 JSON, expiring within 60 seconds or earlier at the helper deadline or a recognized JWT expiry |
| `serve` | Foreground daemon for troubleshooting |

Interactive setup and import reveal the key on the controlling terminal. Type
`verify` to paste a copy from your saved backup with input hidden. A mismatch
cancels before enrollment. Type `saved` to acknowledge the backup and proceed
directly. Without a controlling terminal, use `--recovery-key FILE` for import
or `--key FILE` for recovery. Commands that use file paths never put the key in
their arguments. `path` needs no daemon or browser and fails if the requested
file is absent. An interrupted edit is listed by `status`, not selected by `path edit`.

On an incomplete vault or an unresponsive helper, `status` exits with code 1.
Both human and JSON output report known plaintext edits and a suggested next
action. In JSON, `problems` and `next_action` describe the failure.
`fully_locked: false` also covers uncertainty. While automatic prompts are
paused, `automatic_unlock_paused_until` gives the UTC deadline.

For `config repair`, select the same linked file you used for setup. An existing
generated file, an open edit, or a client path pointing elsewhere prevents
repair. Approval rebuilds the generated client file from the selected encrypted
generation, including its saved context and namespaces. Local selection changes
since the encrypted save may need to be repeated. A missing client link or
encrypted vault requires a different recovery path. See the README's backup
and recovery instructions.

## Supported kubeconfig inputs

Import takes one single-document v1 Config, up to 4 MiB, without `KUBECONFIG`
merging. Inline bearer tokens, verified HTTPS, supported public cluster fields,
and named contexts are accepted. Legacy `preferences` are kept in the encrypted
editable source and omitted from generated client files and recovery exports.
Token files, client certificates, exec/auth-provider, extensions outside
`preferences`, and unknown fields fail without executing any imported command.
For these authentication methods select a file with inline bearer tokens.
Setup validates a selected source before requesting security-key approval,
including when attaching a different file to an existing vault.
The generated kubeconfig contains the proxy address in readable form. Use an
HTTP, HTTPS, or SOCKS5 `proxy-url` without embedded credentials, a query, or a
fragment. If an older vault contains a proxy query or fragment, use
`config unlock`, correct the proxy in the edit file, and close the editor before
`config lock --accept-connection-changes`. Review older generated files and
any copies if the old URL contained a secret. With only an old encrypted backup,
use `recover --out NEW-FILE`, correct the private export, then run `setup NEW-FILE`.
Standalone import rejects symlink sources. Setup preserves client symlinks by managing their resolved regular target. Both reject symlink CA and recovery files. Recovery identities
must be owned by this user, mode 0600, and not hard-linked. Outputs never overwrite.
CA data accepts certificate PEM blocks only, without PEM headers or unrelated
contents. Both generated and portable configurations must fit the 4 MiB reader
limit after embedding CAs. Oversized candidates are rejected before commit.

Close the editor before `config lock`. A detected concurrent change fails the
save and preserves plaintext. A failure after commit explicitly says the vault
was saved. An interrupted finalization can leave `STATE/edit/saving`. Either
edit path keeps `fully_locked` false. Inspect every returned `edit_paths` entry
and preserve desired text before explicit discard. Ordinary lock/stop preserve
both paths. See [editing](DEVELOPMENT.md#interrupted-edits) for recovery.

`config lock` returns `changed: false` when the helper verifies that an edit
still matches the generation opened for editing. No new generation or second
browser page is needed. A committed save returns `changed: true`. Restarting
or locking the helper during an edit discards its in-memory comparison and
requires the usual authenticated save. Both successful paths clear the session.

The generated `STATE/current/kubeconfig` uses an absolute binary path, exec v1,
`interactiveMode: Never`, and `provideClusterInfo: true`. Clients may change
namespace/current-context; other mutations are checked before credential release.
The order of named clusters, users and contexts can change. Generated exec
environment lists may be absent, null or empty. A nonempty list, a different
command or argument sequence, or a changed binding fails validation.
Exec requests support absent/null cluster extensions and reject nonempty ones;
see [upstream exec types](https://github.com/kubernetes/client-go/blob/master/pkg/apis/clientauthentication/v1/types.go).

The current vault metadata format is version 1.
Encrypted generations are retained until explicitly pruned. Pruning refuses to run with an open edit. Standalone backups and encrypted rollback copies remain usable after pruning. See
[editing and limitations](ARCHITECTURE.md#editing-and-limitations).

## Client kubeconfig link

`config link` changes `~/.kube/config` only when asked and only after an import.
It targets `STATE/current/kubeconfig`, which stays at the same path across edits.
kubectl still honors `KUBECONFIG` and `--kubeconfig`. If a client already
references another file, use `config link --kubeconfig FILE` and the same flag
with `config unlink`. A client using an imported copy needs a file reference
for the link to affect it.

Setup and link store the original as `FILE.before-kubeconfig-vault.age`. A private
receipt in the vault directory records its digest and resolved client path. Keep
both for authenticated unlink. A missing or substituted backup stops restoration.

If the client path was empty, `config link` records that fact before creating
its symlink. `config unlink` can then remove the symlink and its receipt.
After an interruption that leaves only the receipt, repeat `config link` to
attach the client or `config unlink` to finish detaching it. A replacement
client file or conflicting backup is preserved.

Older releases created some symlinks without a receipt. If both the receipt
and original backup are missing, Vault keeps the symlink because it cannot
tell whether a backup was lost. Locate the original backup first. If you
independently know that the client path was originally empty, you can remove
just the managed symlink and run `config link` again to record that fact.

For multiple files in `KUBECONFIG`, pass one path to setup. Use
`config unlink --kubeconfig FILE` for a file selected explicitly. With a single
`KUBECONFIG` entry, setup, link and unlink select that file automatically.
Referenced CA paths are resolved against the selected client path. Existing symlinks
are preserved and the final target becomes the managed link. Changing that target
affects every other reference to it. Close other editors before setup or unlink.

An old regular plaintext backup is migrated only after the encrypted replacement
has been verified. For a legacy symlink backup, use the old rollback with
`config unlink` first, then run setup. An old backup with unsupported contents
is preserved for manual handling. When setup reports interruption, leave the
original and encrypted backup in place and rerun. A killed client or helper
can leave a client-go `.lock` file. After confirming that every Vault or
kubectl config writer using that file has exited, remove its stale lock and retry.

Restore accepts only a trusted backup and its recovery key. It rebuilds a portable
config with embedded CAs. Source formatting and relative file references are
specific to the original laptop. Use authenticated unlink there for exact bytes.

`config edit` uses VISUAL, then EDITOR, then vi. It accepts an executable path
or an executable with whitespace-separated arguments. It supplies `--wait` to
known GUI editors. For other launchers configure their foreground option.
An unsuccessful editor exit leaves the edit open. Use the reported edit path
and `config lock` to finish, or explicitly discard it.
