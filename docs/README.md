# Using Kubeconfig Vault

Start with [installation and setup](../README.md#install-and-set-up). Use the sample below to try validation, or jump to [connecting](#connect-with-kubectl-or-freelens), [editing](#edit-and-save), or [recovery](#choose-a-recovery-path).

## Try a sample kubeconfig

Open the [demo kubeconfig](../examples/kubeconfig.yaml) on GitHub and select **Download raw file**. In the folder where you saved it, run:

```sh
kubeconfig-vault setup --check kubeconfig.yaml
```

Expect **Supported kubeconfig. No files changed.** This checks the local input format without opening a browser, contacting Kubernetes, or creating a vault. The demo names a reserved example domain and contains a dummy token.

To practice real enrollment with the demo, keep it in a short temporary path and give it a separate vault. From the same directory:

```sh
demo=$(mktemp -d)
cp kubeconfig.yaml "$demo/config"
kubeconfig-vault --state-dir "$demo/vault" setup "$demo/config"
kubeconfig-vault --state-dir "$demo/vault" status
```

When you finish, run `kubeconfig-vault --state-dir "$demo/vault" stop` to close the demo helper. The demo cannot log in to a cluster. For your own kubeconfig, run `kubeconfig-vault setup --check FILE` first. Each user needs either an inline token or both embedded client certificate fields. Certificate fields require complete base64-encoded PEM. A literal `...` is a placeholder. For a private cluster CA, use its real public CA bundle. Leave TLS verification enabled.

## Connect with kubectl or Freelens

Use kubectl with the same kubeconfig path you selected during setup. A command that contacts the API server asks the helper for credentials. A local command such as `kubectl config current-context` only reads settings and can succeed while the vault is locked.

Freelens can share the same session when it reads the linked file. If it uses an independently imported copy, point its kubeconfig sync at the linked path and reconnect. Approving one client’s request unlocks the helper for the other. The session expires one hour after approval by default. Requests do not extend it.

| What you see | What to do |
| --- | --- |
| An unexpected unlock page | Choose **Decline request**. Automatic prompts pause for ten minutes. `kubeconfig-vault status` shows the deadline. |
| A client reports that its credential is not approved for the cluster | Check that it uses the client path selected during setup. An old copy can refer to a previous credential ID, server, or TLS configuration. A locked helper rejects these stale requests before opening the browser. |
| The browser’s security-key prompt was dismissed | Automatic requests can retry after 30 seconds. Run `kubeconfig-vault unlock` to retry immediately. |
| Yubico Authenticator has no entry for the vault | The vault creates a non-discoverable credential. A successful unlock tests it directly. |
| A running client still works just after `lock` | The helper clears its session immediately. It asks clients to fetch credentials again within 60 seconds, or sooner if the session or a recognized credential expires. A client that honors this deadline can keep using its cached credential until refresh. A copied token or private key can still work for as long as the API server accepts it. An established watch, port-forward or shell can also stay connected. For urgent containment, contact the cluster administrator. |

## Edit and save

Switch contexts and namespaces with the usual `kubectl config use-context NAME` and `kubectl config set-context --current --namespace NAME`. To change a token, server address, certificate or user mapping, edit the encrypted source through the helper.

Saving keeps the client's selected context and namespaces when the edit leaves those choices alone. If you remove the context currently selected in your client, the client switches to the saved source's `current-context`. An explicit selection in your edit takes precedence.

```sh
kubeconfig-vault edit
```

Approve the unlock, make your changes, save, and close the editor. The helper verifies the changes and removes the plaintext edit after a successful save. It prints **Changes encrypted and verified.** Closing an unchanged edit normally prints **No changes.** Vault uses `VISUAL`, then `EDITOR`, then `vi`. Choose an editor that waits until you close the file and disable any plaintext backup copies it makes.

For a separate unlock → edit → lock workflow, run `kubeconfig-vault config unlock`. Get the filename with `kubeconfig-vault path edit`, open it in your editor, and close the editor before running `kubeconfig-vault config lock`. If you intentionally changed a cluster address, TLS trust, or user mapping, review the edit before running `kubeconfig-vault config lock --accept-connection-changes`.

### If a save is interrupted

Run `kubeconfig-vault status`. An open edit is plaintext and can survive a crash, logout, or `lock`. If validation failed, fix the file and retry `config lock`. If status lists both an edit and an interrupted-save path, preserve the changes you need from each in a private location first. `kubeconfig-vault config discard` deletes **both** working copies. You can then unlock a fresh edit and apply the changes you preserved.

## Back up your latest changes

```sh
kubeconfig-vault backup cluster-backup.age
kubeconfig-vault recover cluster-backup.age --check
```

Choose a new filename for each backup. The first command copies the current encrypted save. The second prompts for your recovery key with input hidden and checks that it can decrypt the backup. Store the backup away from the laptop and the private key separately. The encrypted rollback beside your kubeconfig holds the **original** from setup. Later saves are included in a **new backup**.

## Choose a recovery path

| What happened | Action |
| --- | --- |
| The generated client file was deleted, but your kubeconfig still links to the vault | Run `kubeconfig-vault status`. If it suggests `kubeconfig-vault config repair`, run it and approve with the security key. This restores the last encrypted save. Select your context or namespace again if you changed it afterward. |
| You have a new laptop | Install the CLI. In an unused state directory, run `kubeconfig-vault restore cluster-backup.age`. Use the offline key and enroll the security key you want to use. Then run `kubeconfig-vault config link` at the intended client path. |
| You lost the security key on a laptop that still has the old vault | Use [a separate vault and client path](#replace-a-lost-security-key-on-the-same-laptop) to test the replacement. |
| You need a portable plaintext copy and have the offline key | Run `kubeconfig-vault recover cluster-backup.age --out recovered-config`. Choose a new file. The output contains live credentials and embedded CA certificates. |
| You still have the YubiKey and want a plaintext copy of the latest save | Run `kubeconfig-vault export latest-config` and approve fresh authentication. Use a new output filename. |

Only restore a backup from storage you trust. If the encrypted generation or its metadata is unavailable, follow the action printed by `status`. Repair is limited to a missing generated client file. [Status and repair details](INTERFACE.md#status-and-repair)

### Replace a lost security key on the same laptop

Use your encrypted backup, offline recovery key, and replacement security key. Pick unused paths for both the new vault and its client file:

```sh
new_vault="$HOME/.kcv-replacement"
new_config="$HOME/.kube/config-replacement"
kubeconfig-vault --state-dir "$new_vault" restore cluster-backup.age
kubeconfig-vault --state-dir "$new_vault" config link --kubeconfig "$new_config"
kubectl --kubeconfig "$new_config" get namespaces
```

Use a read-only kubectl command your account is allowed to run. Once verified, you can select the new client path in Freelens and set `KUBECONFIG` to it in your shell. Keep the old files until you have verified access and saved a fresh backup.

## Undo setup

Close kubeconfig editors and quit clients that may request credentials. If you want to keep edits made since setup, make a current backup or export first. Then run:

```sh
kubeconfig-vault config unlink
```

Approve with your YubiKey. For a client that had an original file, the helper restores its exact pre-setup bytes as a private **plaintext** kubeconfig. For a client linked at a previously empty path, it removes the managed link. If you selected a custom file, pass `--kubeconfig FILE`. Keep the vault and its encrypted rollback together until unlink succeeds.

[All commands and supported inputs](INTERFACE.md) · [Where keys and credentials live](ARCHITECTURE.md) · [Contributor guide](DEVELOPMENT.md)
