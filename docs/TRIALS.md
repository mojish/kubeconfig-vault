# Try the complete workflow with disposable credentials

Use a fresh Linux or macOS test account or VM with Chrome, kubectl, Node.js 22.12 or newer, OpenSSL, and a USB security key with WebAuthn PRF. The fixture serves a single namespace over HTTPS on loopback. You can test setup, editing, recovery, and unlink without access to a Kubernetes cluster.

## Select the application and test code

For this trial, use the **v0.5.1 binary** (application commit `f8e41c441168ff68f3cdef6bbb3cb4874b112f56`). The test scripts come from a later commit that includes the output-capture and timeout fixes. Record both commits with your result. [Application release](https://github.com/mojish/kubeconfig-vault/releases/tag/v0.5.1) · [Pinned test source](https://github.com/mojish/kubeconfig-vault/tree/69561023208b805e42943460039540bf692f11e3)

Follow [Install from downloaded files](README.md#install-from-downloaded-files) using the v0.5.1 assets in the disposable account. Set `export KUBE_UNLOCK_TEST_BINARY="$(command -v kubeconfig-vault)"`. For a Mac browser download, follow the [first-launch steps](MACOS.md#check-the-download-and-first-launch) and keep the executable path they set.

In Terminal 1, unpack the pinned scripts into a new directory. This also works without Git.

```sh
export KCV_TEST_HARNESS_REVISION=69561023208b805e42943460039540bf692f11e3
harness_dir=$(mktemp -d)
curl -fL -o "$harness_dir/source.tar.gz" \
  "https://github.com/mojish/kubeconfig-vault/archive/$KCV_TEST_HARNESS_REVISION.tar.gz" &&
  tar -xzf "$harness_dir/source.tar.gz" -C "$harness_dir" --strip-components=1 &&
  cd "$harness_dir"
```

## Choose a trial

- **Physical certificate on Linux.** From the pinned source directory, run the two commands below. Go is required to generate the temporary certificate. Preflight checks real kubectl and rejects an invalid control. The second command requests physical approval, checks cache reuse, then checks offline recovery while the helper is locked. The key can stay plugged in throughout.
- **Physical Mac and Freelens.** Continue with the [Mac desktop trial](MACOS.md#test-kubectl-and-freelens) from the pinned source. Record the browser download, first launch and physical authentication results individually.
- **First-time user or replacement key.** Follow the hands-on trial below. Record the first step where you need help, even if you finish.

```sh
node age-app/physical.test.mjs --preflight-only --client-certificate &&
  node age-app/physical.test.mjs --keep-key-connected --client-certificate
```

## Hands-on trial

In Terminal 1, run `node age-app/physical.test.mjs --serve-fixture`. For mutual TLS add `--client-certificate` (requires Go). Leave this terminal open until the trial is finished.

In Terminal 2, use the **same disposable account**. Run `kubeconfig-vault --version` and confirm it prints v0.5.1. If you unpacked the binary manually, add its directory to this terminal’s PATH first. At the prompt below, paste the file **path** printed by Terminal 1.

```sh
umask 077
trial_dir=$(mktemp -d)
cd "$trial_dir"
printf 'Disposable kubeconfig path: '
IFS= read -r fixture
export KUBECONFIG="$PWD/config"
cp "$fixture" "$KUBECONFIG" && kubectl get namespaces -o name
```

The initial response should contain `namespace/vault-test`. Use the ordinary [setup and user guide](README.md) for each task.

| Task | How to tell it worked |
| --- | --- |
| Run `kubeconfig-vault setup` and save the offline recovery key separately. Run `kubectl get namespaces -o name` twice. | The first request opens approval and returns `namespace/vault-test`. The next request reuses the session. |
| Run `kubeconfig-vault lock` and repeat the request in a fresh kubectl process. | One fresh approval restores access. |
| Run `kubeconfig-vault edit`. Set the namespace of the current context to `vault-test`, then save and close the editor. | Saving succeeds and `kubectl config view --minify -o 'jsonpath={.contexts[0].context.namespace}'` returns `vault-test`. |
| Run `kubeconfig-vault backup latest.age`, lock the helper, then run `kubeconfig-vault recover latest.age --check` and `kubeconfig-vault recover latest.age --out recovered`. | With the saved offline key, the recovered file has the edited namespace and `kubectl --kubeconfig recovered get namespaces -o name` reaches the API. The recovered file contains disposable plaintext credentials. |
| Run `kubeconfig-vault config unlink --kubeconfig "$KUBECONFIG"`. | `cmp "$fixture" "$KUBECONFIG"` exits successfully. Unlink restores the original bytes from setup. The encrypted backup contains the later edit. |

### Try a second physical key

Keep the fixture running on the same host. End the original session with `kubeconfig-vault stop`. Use only the replacement key for the following approvals and a **new** vault directory and client path. Have the backup and separately saved recovery key available.

```sh
kubeconfig-vault --state-dir "$PWD/replacement" restore latest.age &&
  kubeconfig-vault --state-dir "$PWD/replacement" config link --kubeconfig "$PWD/replacement-config" &&
  kubeconfig-vault --state-dir "$PWD/replacement" lock &&
  kubectl --kubeconfig "$PWD/replacement-config" get namespaces -o name
```

A fresh approval on the replacement key must return `namespace/vault-test`. Confirm the replacement config also has the saved namespace. End its helper with `kubeconfig-vault --state-dir "$PWD/replacement" stop`. The loopback address belongs to the host running Terminal 1. For a trial across two machines, use a disposable API reachable by both.

When finished, stop the helper with `kubeconfig-vault stop`, then press Ctrl-C in Terminal 1. The fixture removes its own temporary files. Discard the test account or VM, including the working copy, plaintext recovery export and disposable recovery material.

Record passed, blocked or inconclusive for the stages you actually attempted. Include the binary tag and commit, test-source commit, OS and CPU, browser, client versions, credential type, and whether the key was physical or virtual. A short stage and observation are sufficient. [Compatibility report](https://github.com/mojish/kubeconfig-vault/issues/new?template=compatibility.yml)
