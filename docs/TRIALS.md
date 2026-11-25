# Try Kubeconfig Vault with disposable credentials

## Hands-on trial

Practice saving, recovering, and undoing setup in one terminal. Use the [released CLI](../README.md#install-and-set-up), kubectl, and your usual editor. The sample has a fake token and a reserved server address. All commands below use a temporary vault and sample files.

You need one security key to set up, edit, and unlink. **Recovery itself needs only the encrypted backup and the offline recovery key.** If you already have those, go straight to the [recovery commands](README.md#choose-a-recovery-path).

### 1. Protect the sample

```sh
trial=$(mktemp -d /tmp/kcv-trial.XXXXXXXX)
vault() { kubeconfig-vault --state-dir "$trial/vault" "$@"; }
curl -fL -o "$trial/original" https://raw.githubusercontent.com/mojish/kubeconfig-vault/v0.6.0/examples/kubeconfig.yaml &&
  cp "$trial/original" "$trial/config" &&
  vault setup "$trial/config"
```

Save the disposable offline recovery key when the CLI shows it. Complete the three enrollment steps in the browser. Keep the same terminal open.

### 2. Back up, edit, and back up again

```sh
vault backup "$trial/before.age"
vault edit
```

Under the current context’s `context:` entry, add `namespace: practice` at the same indentation as `user:`. Save, close the editor, and approve the encrypted save. Then run:

```sh
vault backup "$trial/after.age"
vault backup --compare "$trial/after.age"
vault lock
```

The new backup should match. The earlier backup still contains the original namespace setting.

### 3. Recover the saved edit

```sh
vault recover "$trial/before.age" --check
vault recover "$trial/after.age" --out "$trial/recovered"
kubectl --kubeconfig "$trial/recovered" config view --minify -o 'jsonpath={.contexts[0].context.namespace}{"\n"}'
```

Paste the offline recovery key at each hidden terminal prompt. The first command verifies that the older backup decrypts. The last command should print **practice**. It reads the recovered file locally, so no cluster, browser, or YubiKey approval is needed here.

### 4. Undo setup

```sh
vault config unlink --kubeconfig "$trial/config"
cmp "$trial/original" "$trial/config" && echo "Original restored exactly"
vault stop
```

Approve unlink with the enrolled security key. The success message means the sample file matches the original byte for byte. The recovered copy still contains the edit. You can now delete the temporary trial directory and discard the disposable recovery key.

## Select the application and test code

Use the **v0.6.0 binary and test scripts**. Both come from commit `70ca239c885e5d39333698f7594b7a64f49954ae`. Record the application and test revisions separately if you try a different combination. [Application release](https://github.com/mojish/kubeconfig-vault/releases/tag/v0.6.0) · [Pinned test source](https://github.com/mojish/kubeconfig-vault/tree/70ca239c885e5d39333698f7594b7a64f49954ae)

Follow [Install from downloaded files](README.md#install-from-downloaded-files) using the v0.6.0 assets in the disposable account. Set `export KUBE_UNLOCK_TEST_BINARY="$(command -v kubeconfig-vault)"`. For a Mac browser download, follow the [first-launch steps](MACOS.md#check-the-download-and-first-launch) and keep the executable path they set.

Unpack the pinned scripts into a new directory. This also works without Git.

```sh
export KCV_TEST_HARNESS_REVISION=70ca239c885e5d39333698f7594b7a64f49954ae
harness_dir=$(mktemp -d)
curl -fL -o "$harness_dir/source.tar.gz" \
  "https://github.com/mojish/kubeconfig-vault/archive/$KCV_TEST_HARNESS_REVISION.tar.gz" &&
  tar -xzf "$harness_dir/source.tar.gz" -C "$harness_dir" --strip-components=1 &&
  cd "$harness_dir"
```

## Choose a trial

- **Physical certificate on Linux.** From the pinned source directory, run the two commands below. Go is required to generate the temporary certificate. Preflight checks real kubectl and rejects an invalid control. The second command requests physical approval, checks cache reuse, then checks offline recovery while the helper is locked. The key can stay plugged in throughout.
- **Physical Linux and Freelens.** Run the certificate preflight below. For the second command, use `node age-app/physical.test.mjs --linux-freelens --client-certificate`. Expect four browser pages in order: enroll the key (three steps), link the disposable kubeconfig, approve Freelens, then approve Freelens again after lock and reopen. Enter a PIN only in Chrome’s security-key dialog. The driver opens Namespaces and checks for fresh data each time. [Linux desktop procedure](DEVELOPMENT.md#test-with-a-physical-yubikey)
- **Physical Mac and Freelens.** Continue with the [Mac desktop trial](MACOS.md#test-kubectl-and-freelens) from the pinned source. Record the browser download, first launch and physical authentication results individually.

```sh
node age-app/physical.test.mjs --preflight-only --client-certificate &&
  node age-app/physical.test.mjs --keep-key-connected --client-certificate
```

## Try a second physical key with a disposable API

For this optional hardware trial, use a fresh test account, the pinned scripts above, and two keys. Run `node age-app/physical.test.mjs --serve-fixture` in one terminal and leave it running. In a second terminal, follow steps 1–3 of the hands-on trial, copying the fixture path printed by the first terminal to `"$trial/original"` in place of the sample download. Run `cd "$trial"` and `vault stop`. Use only the replacement key for the following approvals and a **new** vault directory and client path. Have the backup and separately saved recovery key available.

```sh
kubeconfig-vault --state-dir "$PWD/replacement" restore after.age &&
  kubeconfig-vault --state-dir "$PWD/replacement" config link --kubeconfig "$PWD/replacement-config" &&
  kubeconfig-vault --state-dir "$PWD/replacement" lock &&
  kubectl --kubeconfig "$PWD/replacement-config" get namespaces -o name
```

A fresh approval on the replacement key must return `namespace/vault-test`. Confirm the replacement config also has the saved namespace. End its helper with `kubeconfig-vault --state-dir "$PWD/replacement" stop`. The loopback address belongs to the machine running the fixture. For a trial across two machines, use a disposable API reachable by both.

When finished, stop the fixture with Ctrl-C and discard the test account’s disposable files. Record the release, test-source commit, platform, client, credential type, and first confusing step. A blocked attempt is useful too. [Compatibility report](https://github.com/mojish/kubeconfig-vault/issues/new?template=compatibility.yml)
