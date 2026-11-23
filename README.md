# Kubeconfig Vault

Use your YubiKey to unlock an existing Kubernetes bearer token on your laptop.
Run kubectl or open Freelens as usual. The first request opens a local browser
page. After you approve it, both clients can share the session for up to one
hour. Your cluster continues to validate the same token.

For Linux and macOS. Setup supports kubeconfigs with inline bearer tokens and
verified HTTPS. See [compatibility](#compatibility) for tested configurations.

## Install and set up

If upgrading from v0.2.0 or v0.1.1, first run `kube-unlock-age stop`. Install
into the same directory so existing kubeconfigs can keep calling the old name.

Download the [GitHub release](https://github.com/mojish/kubeconfig-vault/releases/latest) installer:

```sh
curl -fL -o install.sh https://github.com/mojish/kubeconfig-vault/releases/latest/download/install.sh &&
  sh install.sh
```

If your vault is already set up with v0.2.0, you're done. Run
`kubeconfig-vault status` to see its state.

For a new vault, close any editors writing your kubeconfig, then run:

```sh
kubeconfig-vault setup
```

If the shell cannot find the command, use `~/.local/bin/kubeconfig-vault setup`.
Setup uses `~/.kube/config` or the single file selected by `KUBECONFIG`. For
a list of files, choose one with `kubeconfig-vault setup FILE`. For an existing
symlink, setup prints the target it will replace. All aliases to that target
will use the vault.

1. Reveal your offline recovery key in the terminal and save it separately.
   Type `saved` once you have a copy. Your terminal and clipboard may retain it.
2. Complete the three numbered steps in the browser with your security key.
   Enter its PIN in the browser's security-key prompt.
3. Run a familiar read-only kubectl command or reconnect in Freelens.
   Clients already reading the selected file pick up the vault through that path.

Setup verifies both decryption methods, saves an encrypted copy of your exact
original, and switches the client file. Repeat setup to resume. When upgrading
from v0.1.1, run setup to convert a regular plaintext rollback copy using your
existing vault and key.

## Everyday use

| To | Run |
| --- | --- |
| Edit in your normal editor | `kubeconfig-vault config edit` |
| See the session and open edits | `kubeconfig-vault status` |
| End the helper session early | `kubeconfig-vault lock` |
| Undo setup and restore the original plaintext file | `kubeconfig-vault config unlink` |

Editing creates a private plaintext file. Set `VISUAL` or `EDITOR` to an editor
that waits until you close the file. Disable editor backups for sensitive files.
If validation fails, the edit is retained. The [CLI reference](docs/INTERFACE.md)
covers resuming edits, reviewing changes to connection settings, and custom paths.
Locking preserves open edits. Kubernetes clients may continue using a token
they already received.

## Back up and recover

Save the encrypted backup somewhere separate from the laptop, and store the
recovery key separately from that backup. Use a new filename for each backup.

```sh
kubeconfig-vault backup cluster-backup.age
kubeconfig-vault recover cluster-backup.age --check
```

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
| macOS, Apple Silicon and Intel | Native build, test and package checks. Physical USB key and Freelens GUI qualification pending |

Use a browser and authenticator that support WebAuthn PRF. The binaries and
browser support are experimental. The project awaits independent security
review. See [security boundaries](docs/ARCHITECTURE.md),
[private vulnerability reporting](SECURITY.md), and
[development and platform tests](docs/DEVELOPMENT.md).
