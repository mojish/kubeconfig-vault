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
| `status [--json]` | Human-readable session state on a terminal, JSON when piped or requested. JSON includes session state, expiry, primary `edit_path`, all `edit_paths`, and `fully_locked` |
| `unlock` | Fresh browser authentication and an absolute credential session |
| `lock` / `stop` | Cancel authentication and clear cache; stop also exits daemon |
| `config unlock` | Fresh authentication and a plaintext edit file |
| `config lock [--accept-connection-changes]` | Validate, encrypt, verify, commit, delete edit |
| `config discard` | Delete normal and interrupted-save edits and clear cache |
| `config link [--kubeconfig FILE]` | Link the default config or a selected file to the generated client config |
| `config unlink [--kubeconfig FILE]` | Restore the backed-up entry, or remove the managed link if it had no original |
| `export NEW-FILE` | Fresh authentication and portable plaintext export |
| `recover VAULT.age --out NEW-FILE` | Offline recovery. Paste the key at a hidden terminal prompt. |
| `recover VAULT.age --key FILE --out NEW-FILE` | Offline recovery using an existing private key file |
| `credential ID` | ExecCredential v1 JSON, bounded by session/token expiry |
| `serve` | Foreground daemon for troubleshooting |

Interactive import shows the key only when requested. Type `saved` to start
enrollment. Without a controlling terminal, use `--recovery-key FILE` for import
or `--key FILE` for recovery. Commands that use file paths never put the key in
their arguments. `path` needs no daemon or browser and fails if the requested
file is absent. An interrupted edit is listed by `status`, not selected by `path edit`.

## Supported kubeconfig inputs

Import takes one single-document v1 Config, up to 4 MiB, without `KUBECONFIG`
merging. Inline bearer tokens, verified HTTPS, supported public cluster fields,
and named contexts are accepted. Legacy `preferences` are kept in the encrypted
editable source and omitted from generated client files and recovery exports.
Token files, client certificates, exec/auth-provider, extensions outside
`preferences`, and unknown fields fail without executing any imported command.
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

The generated `STATE/current/kubeconfig` uses an absolute binary path, exec v1,
`interactiveMode: Never`, and `provideClusterInfo: true`. Clients may change
namespace/current-context; other mutations are checked before credential release.
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
An initially absent client entry has no rollback copy and unlink removes the link.

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
