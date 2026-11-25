# Verify a release on a Mac

This is a volunteer test for a **physical USB YubiKey and the Freelens desktop app**. It checks how a browser download behaves on your Mac, then verifies that Freelens can unlock, read a namespace and reconnect using your physical key. Hosted Mac runners have exercised the desktop with a virtual authenticator. [Current evidence](COMPATIBILITY.md)

Use a fresh macOS account, leave the YubiKey plugged in, and set Chrome as the default browser. Install Freelens, kubectl, OpenSSL and Node.js 22.12 or later. Quit Freelens with Command-Q before starting. The script creates a temporary kubeconfig, recovery key, Freelens profile and local test API. Keep personal clusters and synced browser accounts out of the test account.

## Check the download and first launch

To collect a hosted comparison, run the **Verify public installation** workflow, enter a published tag, and select the macOS download option. It downloads through Chrome, verifies the release asset, expands it with Archive Utility and records quarantine before the first command-line launch. The log also reports Gatekeeper's state on that runner. Record your Mac's result separately. [Apple's guide to opening downloaded apps](https://support.apple.com/en-us/102445)

1. In Chrome, download `SHA256SUMS` and the macOS archive from the **same release** into an empty Downloads folder. Choose `darwin-arm64` for Apple Silicon or `darwin-amd64` for Intel. On Apple Silicon, use a native Terminal for the commands below. A Terminal running under Rosetta reports the Intel architecture. Keep the downloaded archive. [GitHub releases](https://github.com/mojish/kubeconfig-vault/releases)
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

For v0.5.1, keep the same Terminal window and follow [Select the application and test code](TRIALS.md#select-the-application-and-test-code). This keeps the downloaded executable selected while using the pinned, newer test scripts. From the extracted test-source directory, run the token trial below. It needs no Go build or npm installation.

```sh
node age-app/physical.test.mjs --preflight-only &&
  node age-app/physical.test.mjs --macos-freelens
```

For a certificate trial, install Go for the [certificate fixture](../age-app/test-support/client-certificate.mjs). From the same source directory, run `node age-app/physical.test.mjs --preflight-only --client-certificate`, then `node age-app/physical.test.mjs --macos-freelens --client-certificate`.

Preflight checks the binary and uses kubectl against the test API. The desktop test then prints `WAIT` prompts. If Freelens is outside `/Applications/Freelens.app`, first set `KUBE_UNLOCK_TEST_FREELENS` to the executable inside its app bundle.

| When the script asks | What to do | Evidence of success |
| --- | --- | --- |
| Enroll and link | Complete the three numbered browser steps with the USB key. Approve the separate request to link the temporary kubeconfig. Enter a PIN only in Chrome’s security-key dialog. | Enrollment and attachment complete. |
| Unlock for kubectl | Approve the first request. Leave the key connected. | A real kubectl request reaches the local API. Two more processes share the session after context and namespace changes. |
| Open Freelens | Open the `synthetic` cluster and its **Namespaces** view. If missing, add the printed temporary path under **Preferences → Kubernetes → Kubeconfig Syncs**. Use Command-Shift-G in the file picker. | `vault-test` appears. The script confirms an authenticated namespace-list request. |
| Reconnect | Quit with Command-Q when asked. The script locks the vault and relaunches Freelens. Open the same cluster, approve the fresh unlock, open **Namespaces**, and quit when prompted. | `vault-test` appears again and the second authenticated request is detected. |
| Decline and recover | Click **Decline request** on the last unlock page. Let the script finish. | kubectl is refused, the helper stays locked, and offline recovery succeeds without a browser prompt. |

The test API contains one namespace and no workloads. The current preflight also checks the empty Pod lists that Freelens requests for the cluster and namespace. Other views may be empty. The script cleans up its own processes and temporary files on completion or Ctrl-C. Close the remaining test browser tabs.

## Report results

Include the binary tag and source commit, the test-source commit, Mac CPU, archive, macOS version, Chrome, Freelens and kubectl versions, and YubiKey model. Record the quarantine and first-launch outcome, then whether physical approval and each authenticated namespace read succeeded. A blocked first launch or an unattempted desktop trial is a reportable outcome. A stage and a short observation are sufficient. Omit keys, PINs, serial numbers, browser URLs, kubeconfigs and full logs.
