# Kubeconfig Vault

Unlock an existing Kubernetes token with your YubiKey. The first `kubectl`
request opens a local browser page. After you approve it, commands share an
unlocked session for up to one hour. Your cluster keeps using its existing token.

This experimental tool is for kubeconfigs with **inline bearer tokens** and
verified HTTPS endpoints. If your kubeconfig uses a login plugin (`exec`), a
client certificate, or a token file, use your existing setup. See the
[supported inputs](docs/INTERFACE.md#supported-kubeconfig-inputs).

## 1. Install

Install the [latest release](https://github.com/mojish/kubeconfig-vault/releases/latest)
on Linux or macOS. The installer chooses the x86-64 or ARM64 binary, checks its
SHA-256, and installs it in `~/.local/bin`. Go and Node.js are only needed for
source builds.

```sh
curl -fL -o install.sh https://github.com/mojish/kubeconfig-vault/releases/latest/download/install.sh &&
    sh install.sh
```

If you already cloned the repo, run `./install.sh` from its root. For offline
installation, a source build, or macOS download restrictions, see the
[installation options](docs/DEVELOPMENT.md#installation-options).

For the steps below, you need `kubectl` and a browser and security key that
support WebAuthn PRF. Chrome with a USB YubiKey passed on Linux. You can start
with a [dummy hardware test](docs/DEVELOPMENT.md#test-with-a-physical-yubikey).

```sh
vault="$HOME/.local/bin/kube-unlock-age"
"$vault" --version
```

Run the next blocks in the same terminal. In another terminal, set `$vault`
again. Keep the binary at this path because the generated kubeconfig points to it.

## 2. Import once and save the recovery key

```sh
"$vault" import "$HOME/.kube/config"
```

Use the path to your existing kubeconfig if it lives elsewhere. The command
reads that one file and leaves it intact.

1. Press Enter when the terminal offers to show your recovery key.
2. Copy the key into a password manager you can access separately from this
   laptop, or store it on an encrypted drive. Then type `saved` and press Enter.
3. Complete the numbered steps in the browser. Choose the USB key, and enter
   its PIN only in the browser's security key prompt.

The recovery key is a backup for a lost YubiKey. Anyone with the key and the
vault file can decrypt it, so display it in a private terminal. Terminal
scrollback and clipboard history may retain a copy. The app creates the vault
only after verifying both ways of decrypting it. If enrollment fails before
the vault is created, retry import and save the new key it shows.

## 3. Use kubectl or Freelens

Try a read you already have permission to run.

```sh
vault_config=$("$vault" path kubeconfig) &&
    kubectl --kubeconfig "$vault_config" get namespaces
```

The file from `path kubeconfig` is the one to give to clients. It contains
connection settings and a helper command. After you unlock, the helper gives
kubectl the token. Repeat the command to use the same session without another
browser prompt.

For ordinary `kubectl` commands in this terminal, set `KUBECONFIG` once:

```sh
vault_config=$("$vault" path kubeconfig) &&
    export KUBECONFIG="$vault_config" && kubectl get namespaces
```

This affects the current terminal and its child processes. To switch back,
use a fresh terminal with your normal environment. For **Freelens**, run
`"$vault" path kubeconfig`, copy the printed file path, and add that file to
Freelens as a synchronized kubeconfig so it can see future saves. The bundled
proxy passed testing. Full GUI testing is pending.

## Edit or lock the vault

```sh
"$vault" config unlock && edit_file=$("$vault" path edit) && nano "$edit_file"
```

Replace `nano` with your preferred editor. Save and close the editor before
running `"$vault" config lock` to validate, encrypt, and verify the change.
The editable copy is plaintext, so disable editor backups and autosave copies.
Keep client settings pointed at the generated config from step 3.

Use `"$vault" lock` to clear the session. It preserves any unfinished edit.
See [interrupted edits](docs/DEVELOPMENT.md#interrupted-edits) for how to resume
or discard one. Locking cannot revoke tokens already delivered to clients.

## Back up and recover

Run `"$vault" path vault` to find the encrypted file and copy it to a backup.
Store your recovery key separately. To check recovery, put the backup file
at an accessible path and choose a new output filename.

```sh
"$vault" recover "$HOME/Downloads/vault.age" --out "$HOME/kubeconfig-recovered"
```

Replace the input path with your backup's location. Paste the recovery key at
the hidden prompt and press Enter. Recovery works offline without a browser
or YubiKey. The output is a plaintext kubeconfig. Keep it private.

## Compatibility and security

- Linux has passed physical YubiKey tests with dummy data. Apple Silicon and
  Intel macOS have native CI coverage. Mac browser and physical key testing
  are pending. See the [CI runs](https://github.com/mojish/kubeconfig-vault/actions).
- This protects stored credentials on a trusted laptop. Keep existing plaintext
  configs and their backups protected separately. Protect or remove them only
  after you have verified both vault access and recovery.
- The project uses age and Typage WebAuthn PRF and is awaiting independent
  review. See the [architecture and security boundaries](docs/ARCHITECTURE.md).

[Development and tests](docs/DEVELOPMENT.md) · [CLI reference](docs/INTERFACE.md) · [MIT License](LICENSE)
