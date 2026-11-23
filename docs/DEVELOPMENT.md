# Development and usage

This guide covers the Go/Typage application in `age-app`. Start with the
[README](../README.md) for an overview and quick start. The [historical Python
prototype](legacy-python.md) and [library experiment](guides/age-prf-experiment.md)
have separate instructions; their state is not migrated automatically.

See [continuous integration](guides/continuous-integration.md) for Linux/macOS
checks, dependency updates, and the distinction between CI and hardware testing.

## Age application

This separate experimental binary does not update the installed Python launcher.
Build from `age-app` with Go 1.26.11 or a newer supported patched release and
Node.js 22.12+. `go.mod` enforces the minimum. Node is only a build/test
dependency; the executable embeds bundled browser assets.

```sh
export GOPATH="${TMPDIR:-/tmp}/kube-unlock-go-path"
export GOCACHE="${TMPDIR:-/tmp}/kube-unlock-go-cache"
npm ci --ignore-scripts --no-audit --no-fund
npm run build:web
npm run test:ui
go mod download
go test -race ./...
go vet ./...
go build -o kube-unlock-age .
npm run test:browser
npm run audit:security
```

The integration test compiles a temporary race-instrumented executable. It uses
only temporary synthetic configs, virtual FIDO2, disposable Chrome, real kubectl,
and a local HTTPS API. It requires Chrome, kubectl, and OpenSSL. Override paths
with `KUBE_UNLOCK_TEST_CHROME` and `KUBE_UNLOCK_TEST_KUBECTL`. Optional proxy testing
uses `KUBE_UNLOCK_TEST_FREELENS_PROXY` or the installed Linux proxy executable,
never a real Freelens profile. Test processes and temporary state are cleaned.

`test:ui` needs no browser or credentials. Its delayed-response cases verify that
status polls cannot overlap, re-enable an action during authentication, or replace
a terminal failure with an older step. The browser integration also checks all
three numbered enrollment steps.

`audit:security` runs npm's advisory check and pinned `govulncheck` v1.10.0. It
needs access to public package/checksum services and vulnerability databases.
Review symbol results separately from matches in unused module packages.
It does not upload source or credentials. Keep the build toolchain patched.

Tests cover two-recipient import verification, cold/warm and concurrent requests,
editing failures, verified saves, cache invalidation, cancellation, expiry,
offline recovery, destination binding, tampering, file permissions, and HTTP
Origin/capability/replay boundaries. Cross-compilation does not test macOS runtime:

```sh
env GOOS=darwin GOARCH=arm64 go build -o /tmp/kube-unlock-age-arm64 .
env GOOS=darwin GOARCH=amd64 go build -o /tmp/kube-unlock-age-amd64 .
```

## Age user-operated workflow

Read the [security review](guides/age-security-review.md) for the fixes, tested
scope, editor-concurrency limits, and remaining release qualification.

First qualify this application with a dummy config and your physical YubiKey.
If you already use the Python prototype, keep it until those checks pass.
The following is a later explicit import workflow, not an automatic migration.
Keep the binary in a stable path: the generated exec command points to it.
Global flags precede the command. The offline key directory must already exist.

```sh
./kube-unlock-age recovery-key new /path/to/offline/recovery.txt
./kube-unlock-age --state-dir /path/to/new-private-state import /path/to/source-config --recovery-key /path/to/offline/recovery.txt
./kube-unlock-age --state-dir /path/to/new-private-state status
```

Keep the private recovery file offline separately, with a tested backup. Import
uses it for verification; state stores only its public recipient. The original
source remains unchanged. Only after verification, select `STATE/current/kubeconfig`
in kubectl or Freelens. Real-cluster commands use your existing token. These
instructions do not authorize the assistant to read it or execute migration.

```sh
./kube-unlock-age --state-dir /path/to/new-private-state config unlock
# Open edit_path in your editor, save changes, then close the editor.
./kube-unlock-age --state-dir /path/to/new-private-state config lock
./kube-unlock-age --state-dir /path/to/new-private-state status
```

An edit is plaintext on disk. Disable editor backups, swap, and autosave copies.
Ordinary lock/stop preserve edits; `fully_locked` remains false until cleanup.
Review connection changes before `config lock --accept-connection-changes`.
Validation failure retains your edit. `config discard` deletes it without saving.

If save reports a concurrent edit before commit, close the editor and retry.
If it reports a post-commit conflict or an interrupted save, inspect all paths in
`status.edit_paths`. Preserve any desired text in a private file before using
`config discard`. Then unlock a fresh edit, merge your preserved changes, close
the editor, and lock again. Discard removes both the normal edit and `edit/saving`.
Retained plaintext remains visible in status across restart and ordinary lock.

```sh
./kube-unlock-age recover /path/to/backup/vault.age --key /path/to/offline/recovery.txt --out /path/to/new-recovered-config
```

Recovery needs no browser/daemon, creates portable plaintext, and never overwrites
an existing output. To replace a lost YubiKey, import the recovered config into a
new state directory with the replacement key, verify it, then select the new
generated config. There is no in-place rotation or Python-vault migration command.
Keep backups and originals until recovery has been verified.

## Physical YubiKey qualification

Build the age executable first, then run from `age-app`:

```sh
npm run test:physical -- --preflight-only
npm run test:physical -- --keep-key-connected
```

Preflight checks real kubectl against a temporary dummy HTTPS API without opening
a browser or using a key. The full run starts isolated Chrome at `about:blank`,
then opens two authentication pages. The blank startup window needs no action.
There is no DevTools connection or virtual authenticator. Complete the enrollment
steps and the separate cold-unlock page using the physical USB key. Enter its PIN
only in Chrome.
The command above leaves the key connected and reports the removal check skipped.
Without that flag, type `skip` to keep it connected, or `unplugged` after removing
it. The harness checks cached access and recovery, then removes its processes,
state, profile, and disposable recovery key. It never loads real configs/profiles.
Ctrl+C or the 15-minute deadline cancels and cleans up. Browser operations retain
their five-minute timeout. Executable overrides match the browser integration.
Do not reuse the disposable recovery key. Failures print the phase, never secrets.

The updated Go 1.26.11 binary passed a complete connected-key run on Linux with
Chrome 158.0.8127.36 and a user-operated USB YubiKey:

- Enrollment and native YubiKey/recovery verification before commit succeeded.
  The original dummy source remained unchanged.
- A cold real-kubectl request opened a fresh unlock page and reached the dummy API.
- Two subsequent kubectl processes reused the one-hour session without opening
  another authentication page or extending the session deadline.
- After explicit helper lock, offline recovery produced a standalone config
  accepted by kubectl, without a browser launch or unlocking the helper.
- Cleanup removed the test processes, isolated Chrome profile, dummy vault/configs,
  and disposable recovery key.

The YubiKey stayed connected throughout, as requested. Physical removal was
explicitly skipped, so this run does not establish behavior with the key absent.
It does not qualify macOS runtime, full Freelens GUI behavior, manufacturer
attestation, or independent security review. No real migration ran.

## Security regression tests

The [review regressions](../age-app/review_regression_test.go) are part of the
normal Go suite. From `age-app`, after the build prerequisites above:

```sh
go test -race ./...
```

They require rejection of mixed CA material and unreadable candidates, retention
of concurrent edits, interrupted-edit visibility, and private browser handoff.
They use disposable state and dummy keys. Some bind loopback listeners and launch
fake browser processes. The process-argument test needs Linux procfs and
`/usr/bin/python3` and skips without procfs. The old overlay probes that passed
when bugs were present have been replaced. A regression PASS requires safe behavior
within the [documented scope](guides/age-security-review.md).
