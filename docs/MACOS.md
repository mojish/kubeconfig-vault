# Verify a release on a Mac

This is a volunteer test for a **physical USB YubiKey and the Freelens desktop app**. It answers two questions the hosted tests cannot settle. Will Gatekeeper allow the downloaded binary to run on first launch? Can the desktop app unlock the vault, read a namespace, and reconnect after locking?

Use a fresh macOS account, leave the YubiKey plugged in, and set Chrome as the default browser. Install Freelens, kubectl, OpenSSL and Node.js 22.12 or later. Quit Freelens with Command-Q before starting. The script creates a temporary kubeconfig, recovery key, Freelens profile and local test API. Keep personal clusters and synced browser accounts out of the test account.

## Check the download and first launch

1. In Chrome, download `SHA256SUMS` and the macOS archive from the **same release** into an empty Downloads folder. Choose `darwin-arm64` for Apple Silicon or `darwin-amd64` for Intel. Keep the downloaded archive. [GitHub releases](https://github.com/mojish/kubeconfig-vault/releases)
2. Verify the checksum in Terminal. Continue when the selected archive reports `OK`.

   ```sh
   cd "$HOME/Downloads"
   case "$(uname -m)" in
     arm64)  asset=kubeconfig-vault-darwin-arm64.tar.gz ;;
     x86_64) asset=kubeconfig-vault-darwin-amd64.tar.gz ;;
   esac
   awk -v file="$asset" '$2 == file' SHA256SUMS | shasum -a 256 -c -
   ```

3. Double-click the archive in Finder to expand it. Set the path below to the **extracted executable**. Adjust the folder name if Archive Utility chose a different one. Record the quarantine result **before** the first launch.

   ```sh
   export KUBE_UNLOCK_TEST_BINARY="$PWD/${asset%.tar.gz}/kubeconfig-vault"
   if xattr -p com.apple.quarantine "$KUBE_UNLOCK_TEST_BINARY" >/dev/null 2>&1; then
     echo 'Quarantine present'
   else
     echo 'Quarantine absent or unreadable'
   fi
   "$KUBE_UNLOCK_TEST_BINARY" --version
   ```

| What happens | What to record |
| --- | --- |
| macOS blocks the launch | Stop and record the short warning. Keep the quarantine attribute and security settings intact. |
| A quarantined, previously unopened download prints its version | Record the version and that the quarantined download ran. |
| The attribute is absent, unreadable, or the binary was already approved | Mark the first-launch result inconclusive. You can still run the functional test. |

The shell installer and a download opened in Finder take different paths through macOS. Record which path you tested. [Apple’s first-launch guidance](https://support.apple.com/en-us/102445)

## Test kubectl and Freelens

Run the script from the **same tag** as the binary. A checkout contains it at `age-app/physical.test.mjs`. Alternatively, from the Downloads folder:

```sh
tag=$("$KUBE_UNLOCK_TEST_BINARY" --version | awk '$1 == "kubeconfig-vault" { print $2 }')
curl -fL "https://raw.githubusercontent.com/mojish/kubeconfig-vault/$tag/age-app/physical.test.mjs" -o physical.test.mjs &&
  node physical.test.mjs --preflight-only &&
  node physical.test.mjs --macos-freelens
```

Preflight checks the binary and uses kubectl against the test API. The desktop test then prints `WAIT` prompts. If Freelens is outside `/Applications/Freelens.app`, first set `KUBE_UNLOCK_TEST_FREELENS` to the executable inside its app bundle.

| When the script asks | What to do | Evidence of success |
| --- | --- | --- |
| Enroll and link | Complete the three numbered browser steps with the USB key. Approve the separate request to link the temporary kubeconfig. Enter a PIN only in Chrome’s security-key dialog. | Enrollment and attachment complete. |
| Unlock for kubectl | Approve the first request. Leave the key connected. | A real kubectl request reaches the local API. Two more processes share the session after context and namespace changes. |
| Open Freelens | Open the `synthetic` cluster and its **Namespaces** view. If missing, add the printed temporary path under **Preferences → Kubernetes → Kubeconfig Syncs**. Use Command-Shift-G in the file picker. | `vault-test` appears. The script confirms an authenticated namespace-list request. |
| Reconnect | Quit with Command-Q when asked. The script locks the vault and relaunches Freelens. Open the same cluster, approve the fresh unlock, open **Namespaces**, and quit when prompted. | `vault-test` appears again and the second authenticated request is detected. |
| Decline and recover | Click **Decline request** on the last unlock page. Let the script finish. | kubectl is refused, the helper stays locked, and offline recovery succeeds without a browser prompt. |

The test API exposes only a few resources. Other Freelens views may be empty. The script cleans up its own processes and temporary files on completion or Ctrl-C. Close the remaining test browser tabs.

## Report results

Include the tag, Mac CPU, macOS version, Chrome, Freelens and kubectl versions, and YubiKey model. Record the first-launch result and whether `vault-test` appeared on both connections. The script’s `PASS`, `SKIP`, `FAIL` or `CANCELLED` lines and the last stage reached are sufficient. Omit keys, PINs, serial numbers, browser URLs, kubeconfigs and full logs.
