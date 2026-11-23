# Kubeconfig Vault

Use your YubiKey to unlock an existing Kubernetes bearer token on your laptop.
Run kubectl or open Freelens as usual. The first request opens a local browser
page. After you approve it, both clients can share the session for up to one
hour. Your cluster continues to validate the same token.

For Linux and macOS. Setup supports kubeconfigs with inline bearer tokens and
verified HTTPS. See [compatibility](#compatibility) for tested configurations.

## Install and set up

Download and run the installer from the latest [GitHub release](https://github.com/mojish/kubeconfig-vault/releases/latest).

```sh
curl -fL -o install-kubeconfig-vault.sh https://github.com/mojish/kubeconfig-vault/releases/latest/download/install.sh &&
  sh install-kubeconfig-vault.sh
```

Close any editors writing your kubeconfig, then run the setup command.

```sh
kubeconfig-vault setup
```

If the shell cannot find the command, use `~/.local/bin/kubeconfig-vault setup`.
Setup uses `~/.kube/config` or the single file selected by `KUBECONFIG`. For
a list of files, choose one with `kubeconfig-vault setup FILE`. For an existing
symlink, setup prints the target it will replace. All aliases to that target
will use the vault.

1. Reveal your offline recovery key in the terminal and save it separately.
   Type `verify` to paste your saved copy at a hidden prompt, or `saved` to
   continue after saving it. Your terminal and clipboard may retain the displayed key.
2. Complete the three numbered steps in the browser with your security key.
   Enter its PIN in the browser's security-key prompt. Successful verification
   confirms enrollment. The vault uses a non-discoverable credential, so it
   normally has no entry in Yubico Authenticator’s Passkeys list.
3. Run a familiar read-only kubectl command or reconnect in Freelens.
   Clients already reading the selected file pick up the vault through that path.

Setup verifies both decryption methods, saves an encrypted copy of your exact
original, and switches the client file. If setup is interrupted, run it again to resume.

Running `kubeconfig-vault status` before enrollment reports that setup is needed.
It can also check a stopped vault without starting the helper.

## Everyday use

Switch contexts with `kubectl config use-context NAME`, and set a namespace
with `kubectl config set-context --current --namespace NAME`. Both work on the
linked file. To change a token, cluster address, or certificate, use the vault editor.

If an unlock page appears unexpectedly, select **Decline request**. A background
Kubernetes app can request access. Declining an automatic unlock leaves the vault
locked and pauses automatic requests for 10 minutes. Run `kubeconfig-vault status`
to see when the pause ends, or `kubeconfig-vault unlock` to unlock immediately.

| To | Run |
| --- | --- |
| Edit in your normal editor | `kubeconfig-vault config edit` |
| See the session and open edits | `kubeconfig-vault status` |
| End the helper session early | `kubeconfig-vault lock` |
| Undo setup and restore the original plaintext file | `kubeconfig-vault config unlink` |

Editing creates a private plaintext file. Set `VISUAL` or `EDITOR` to an editor
that waits until you close the file. Disable editor backups for sensitive files.
Closing the editor without changes normally shows **No changes** and skips the
second browser page. Changed files are encrypted and verified before the
plaintext edit is removed. If validation fails, the edit is retained. The [CLI reference](docs/INTERFACE.md)
covers resuming edits, reviewing changes to connection settings, and custom paths.
Locking preserves open edits. A running kubectl or Freelens client can reuse
its last token for up to 60 seconds. Its next request after that needs a fresh
unlock. While the helper is unlocked, those refreshes happen silently. An
existing watch or shell can stay connected. To revoke the token itself, use
your cluster’s credential controls.

## Back up and recover

Save the encrypted backup somewhere separate from the laptop, and store the
recovery key separately from that backup. Use a new filename for each backup.

```sh
kubeconfig-vault backup cluster-backup.age
kubeconfig-vault recover cluster-backup.age --check
```

If kubectl or Freelens loses its linked configuration, run `kubeconfig-vault status`.
If it reports a missing generated kubeconfig, run `kubeconfig-vault config repair`
and approve with your security key. Repair restores the last encrypted save.
You may need to select your context or namespace again.

Backup also works if a client damaged or deleted the generated kubeconfig.
The check asks for the recovery key in a hidden terminal prompt and verifies
that the backup contains a usable config. On a new laptop, install the helper,
bring your trusted backup and recovery key, then run:

```sh
kubeconfig-vault restore cluster-backup.age
kubeconfig-vault config link
```

Restore enrolls a security key and rebuilds client paths for this laptop.
For an offline plaintext export without a YubiKey, run
`kubeconfig-vault recover cluster-backup.age --out recovered-config`.
Treat that output as a live credential.

## Compatibility

| Environment | Evidence |
| --- | --- |
| Linux, Chrome, USB YubiKey | Physical enrollment, unlock, cached access and offline recovery with synthetic credentials |
| Linux, kubectl and Freelens | Automated kubectl and Freelens proxy integration. Earlier Freelens 2.1.0 GUI qualification with an isolated profile |
| macOS, Apple Silicon and Intel | Native build, test and package checks. [Physical YubiKey and Freelens desktop volunteer test](docs/MACOS.md) |

Use a browser and authenticator that support WebAuthn PRF. The binaries and
browser support are experimental. The project awaits independent security
review. See [security boundaries](docs/ARCHITECTURE.md),
[private vulnerability reporting](SECURITY.md), and
[development and platform tests](docs/DEVELOPMENT.md).
