# Development and testing

Start with the [README](../README.md) to build the application. Run the following
from `age-app` after installing dependencies and building the browser bundle:

```sh
go mod download
go test -race ./...
go vet ./...
npm run test:ui
npm run test:browser
npm run audit:security
```

The browser test uses isolated Chrome with virtual FIDO2, real kubectl, and a
local HTTPS API. It needs Chrome, kubectl, and OpenSSL. Set
`KUBE_UNLOCK_TEST_CHROME` or `KUBE_UNLOCK_TEST_KUBECTL` to override the executables.
The optional Freelens proxy check uses `KUBE_UNLOCK_TEST_FREELENS_PROXY` or the
installed Linux proxy. All tests use synthetic credentials and disposable state.

The Go suite covers session expiry, Unix peer identity, authenticated storage,
file handling, editing failures, and HTTP access controls. The Linux
process-argument test uses procfs and `/usr/bin/python3`. `test:ui` checks that
browser polling and click responses keep the correct page state.

[CI](https://github.com/mojish/kubeconfig-vault/actions/workflows/ci.yml) runs
native Go and UI tests on Ubuntu and both macOS architectures. Ubuntu also runs
the browser integration, `npm audit`, and `govulncheck`. The advisory checks
need public package and vulnerability services. Review called symbols separately
from matches in unused module packages. CI uses pinned actions, read-only
permissions, and no configured secrets. Dependabot proposes dependency updates.

## Test with a physical YubiKey

Build `kube-unlock-age` in `age-app`, then run from that directory:

```sh
npm run test:physical -- --preflight-only
npm run test:physical -- --keep-key-connected
```

Preflight verifies kubectl against a dummy API without a key. The full run opens
isolated Chrome and asks you to complete enrollment and then a separate unlock.
The blank Chrome startup window needs no action. Use your USB key and enter its
PIN only in Chrome’s prompt. The check covers import, cold unlock, cached access,
and offline recovery with the key left connected. Ctrl+C or the test deadline
ends the run and cleans up its temporary profile, vault, and recovery key.

Linux has passed this hardware flow. Desktop browser launch and USB key use on
macOS and the full Freelens GUI workflow still need hands-on testing.

## Interrupted edits

Close the editor before `config lock`. Connection and trust changes require
`config lock --accept-connection-changes` after reviewing them. Validation
failures retain the edit. If a save reports that the file changed before commit,
close the editor and retry.

If the vault was committed but cleanup failed, run `status` and examine every
entry in `edit_paths`. Preserve any changes you want in a private file. Then run
`config discard` to clear the edit paths, unlock a fresh edit, merge your changes,
and save again. `config discard` deletes both the edit and the interrupted-save
copy. Ordinary lock and stop preserve them.

For offline recovery, follow the [README](../README.md#recover-offline). If you
replace a lost YubiKey, import the recovered plaintext into a new state directory
with the replacement key and verify it before switching clients. Select the new
state directory with `--state-dir PATH` before the `import` command.
