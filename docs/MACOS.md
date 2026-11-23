# Test a release on a Mac

Use a fresh macOS account for this test. Keep the USB YubiKey connected. You
will connect kubectl and the real Freelens app to a small HTTPS server on this
Mac. Its only namespace is `vault-test`. No company cluster or token is needed.

## Check the download and first launch

1. Sign in to the disposable account. Install Freelens and Chrome, set Chrome
   as its default browser, and quit Freelens with Command-Q. Have Node.js
   22.12 or later, kubectl, and OpenSSL on PATH. Keep the account free of cloud
   sign-ins, kubeconfigs, browser sync, and existing Freelens connections.
2. In Chrome, open the [GitHub releases](https://github.com/mojish/kubeconfig-vault/releases).
   From one release download `SHA256SUMS` and the matching archive into an
   empty Downloads folder. Apple Silicon uses `darwin-arm64` and Intel uses
   `darwin-amd64`. Record the tag. Save the original archive before opening it.
3. Verify your archive in Terminal. Continue only if the output says `OK`.

   ```sh
   cd "$HOME/Downloads"
   case "$(uname -m)" in
     arm64) asset=kubeconfig-vault-darwin-arm64.tar.gz ;;
     x86_64) asset=kubeconfig-vault-darwin-amd64.tar.gz ;;
   esac
   awk -v file="$asset" '$2 == file' SHA256SUMS | shasum -a 256 -c -
   ```

4. Double-click the archive in Finder to expand it with Archive Utility. Set
   the path below to the extracted executable (adjust the folder name if Finder
   chose a different one). Record whether the executable has a quarantine
   attribute **before** its first launch.

   ```sh
   export KUBE_UNLOCK_TEST_BINARY="$PWD/${asset%.tar.gz}/kubeconfig-vault"
   ls -l "$KUBE_UNLOCK_TEST_BINARY"
   if xattr -p com.apple.quarantine "$KUBE_UNLOCK_TEST_BINARY" >/dev/null 2>&1; then
     echo 'Quarantine attribute present'
   else
     echo 'Quarantine attribute absent or unreadable'
   fi
   "$KUBE_UNLOCK_TEST_BINARY" --version
   ```

   Record the version and what macOS did. If macOS blocked the launch, stop
   here and report the warning text. Leave security settings and attributes
   intact. If it ran with the attribute present, report **quarantined download
   ran**. If the attribute was absent or this file had already been approved,
   report **first-launch Gatekeeper check inconclusive**. The functional test
   can still run. A source build and the shell installer exercise different
   download paths. [Apple's first-launch guidance](https://support.apple.com/en-us/102445)

## Test kubectl and Freelens

Use the `physical.test.mjs` from the same release tag. A checkout of that tag
already includes it under `age-app/`. To download just the script and run it:

```sh
tag=$("$KUBE_UNLOCK_TEST_BINARY" --version | awk '$1 == "kubeconfig-vault" { print $2 }')
curl -fL "https://raw.githubusercontent.com/mojish/kubeconfig-vault/$tag/age-app/physical.test.mjs" -o physical.test.mjs &&
  node physical.test.mjs --preflight-only &&
  node physical.test.mjs --macos-freelens
```

The first command that runs Node checks the binary and kubectl without starting
a browser. The desktop test creates its own kubeconfig, recovery key, vault, and
Freelens profile in a temporary directory. If Freelens is installed outside
`/Applications/Freelens.app`, set `KUBE_UNLOCK_TEST_FREELENS` to the full
path of its executable inside the app bundle before starting.

1. In Chrome, complete the three enrollment steps with the USB key. Approve
   the separate request to link the test kubeconfig and then kubectl's first
   unlock. Enter the PIN only in the browser's security-key dialog. The script
   switches contexts, sets a namespace, and checks that two more kubectl
   processes reuse the same one-hour session.
2. The script locks the vault and opens Freelens. Open the `synthetic` cluster.
   If it is missing, add the temporary path printed in Terminal under
   **Preferences → Kubernetes → Kubeconfig Syncs**. In a macOS file picker,
   Command-Shift-G accepts that path. Unlock
   in the browser and open **Namespaces** in Freelens. Look for `vault-test`.
   Other views may be empty because the fixture only serves a few resources.
3. Wait for the terminal to report that Freelens fetched the namespace list
   and kubectl reused the session. Quit Freelens with Command-Q. The script
   locks the vault and relaunches Freelens. Reconnect to the cluster, complete
   the fresh browser unlock and open **Namespaces** again. Quit Freelens when
   prompted. A missing authenticated namespace-list request fails the test.
4. After quitting Freelens the second time, wait for the script to request
   another unlock. Click **Decline request** on the vault page. The script
   checks that kubectl failed and the helper stayed locked.
5. The script locks the helper and checks offline recovery with the temporary
   recovery key. It prints the result, stops its processes, and deletes its
   temporary files. Close the test browser tabs. Ctrl-C also triggers cleanup.

## Report results

Share the release tag, macOS version, Apple Silicon or Intel, Chrome and
Freelens and kubectl versions, YubiKey model, and the Gatekeeper result above. Include
the terminal's `PASS`, `SKIP`, `FAIL`, or `CANCELLED` lines and whether the
namespace appeared in Freelens on both connections. If it failed, the last
stage and any short macOS warning are enough. Keep PINs, keys, kubeconfigs,
browser URLs, full logs, and serial numbers private.
