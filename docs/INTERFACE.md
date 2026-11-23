# CLI and kubeconfig reference

## Options

Defaults are `~/.local/share/kube-unlock-age` on Linux and
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
| `import SOURCE --recovery-key FILE` | New two-recipient vault verified before commit |
| `status` | JSON session state, expiry, primary `edit_path`, all `edit_paths`, and `fully_locked` |
| `unlock` | Fresh browser authentication and an absolute credential session |
| `lock` / `stop` | Cancel authentication and clear cache; stop also exits daemon |
| `config unlock` | Fresh authentication and a plaintext edit file |
| `config lock [--accept-connection-changes]` | Validate, encrypt, verify, commit, delete edit |
| `config discard` | Delete normal and interrupted-save edits and clear cache |
| `export NEW-FILE` | Fresh authentication and portable plaintext export |
| `recover VAULT.age --key FILE --out NEW-FILE` | Offline recovery from standalone ciphertext |
| `credential ID` | ExecCredential v1 JSON, bounded by session/token expiry |
| `serve` | Foreground daemon for troubleshooting |

## Supported kubeconfig inputs

Import takes one single-document v1 Config, up to 4 MiB, without `KUBECONFIG`
merging. Inline bearer tokens, verified HTTPS, supported public cluster fields,
and named contexts are accepted. Token files, client certificates, exec/auth-provider,
nonempty preferences, extensions, and unknown fields fail without executing any
imported command. Symlink source/CA/recovery files are rejected. Recovery identities
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
Encrypted generations are retained. Restore, repair, multi-key enrollment,
in-place key rotation, and migration subcommands are not implemented. See
[editing and limitations](ARCHITECTURE.md#editing-and-limitations).
