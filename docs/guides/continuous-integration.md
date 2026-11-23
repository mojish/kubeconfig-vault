# Continuous integration

The [GitHub Actions workflow](../../.github/workflows/ci.yml) checks the experimental
`age-app` application on pushes, pull requests, and manual dispatch. See the
[workflow runs](https://github.com/mojish/kubeconfig-vault/actions/workflows/ci.yml)
for results.

## Coverage

| Runner | Checks |
| --- | --- |
| Ubuntu 24.04, x64 | Workflow lint, native race tests, Go formatting/vet/build, UI tests, browser integration, dependency advisory scans |
| macOS 15, Apple Silicon | Native race tests, Go formatting/vet/build, UI tests |
| macOS 15, Intel | Native race tests, Go formatting/vet/build, UI tests |

The macOS jobs use [GitHub-hosted runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners);
contributors can run those checks without their own Mac.
Native tests exercise the platform's real Unix peer-credential syscall in both
directions and require closed sockets to fail authentication. They do not exercise
a second OS user, physical USB access, or the default desktop browser launcher.
The Linux process-argument regression uses procfs and is explicitly skipped on Mac.

Linux browser integration uses a virtual authenticator, an isolated Chrome
profile, temporary synthetic configs, and kubectl against a loopback HTTPS API.
Chrome, kubectl, and OpenSSL come from the
[Ubuntu runner image](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md);
their versions are printed before the test. A missing prerequisite fails the job.
The optional installed Freelens proxy is normally absent on hosted runners, so
that check reports a skip. No Freelens GUI or physical-key test runs in CI.

The historical Python prototype and standalone library experiment are outside
this workflow's test scope. Their local commands are linked from
[development](../DEVELOPMENT.md).

## Dependencies and permissions

Actions are pinned to verified release commit hashes. Checkout does not persist
Git credentials; workflow permissions are read-only. Jobs need no configured
secrets, kubeconfig, recovery key, or user browser profile. There is no deployment,
artifact upload, or automatic publishing step.
Linux also validates the workflow and embedded shell with pinned actionlint 1.7.12.

Go comes from the version in `age-app/go.mod`, with automatic toolchain switching
disabled. Node uses the supported 22.x line. `npm ci --ignore-scripts` installs
the lockfile; the explicit bundle step runs afterward. Go verifies its downloaded
modules. Package caches hold dependency/build material, not test profiles or vaults.
The harness uses the same explicit Go cache paths as setup-go.

Linux runs `npm audit` and the pinned `govulncheck` command defined in
`age-app/package.json`. These consult public advisory services. A failed scan
fails CI; a successful scan is not a security audit or proof of exploit absence.
Module matches in unused packages must be distinguished from called symbols.

[Dependabot](../../.github/dependabot.yml) proposes weekly updates to action pins
and the Go/npm dependencies in `age-app` and `experiments/age-prf`. It does not
merge updates. Toolchain patch/support status also needs review; do not assume a
dependency PR automatically updates the Go or Node baseline.

## Running the checks locally

Use the commands in [development](../DEVELOPMENT.md#age-application). The workflow
uses ordinary npm and Go commands and does not depend on company documentation
tools or command wrappers. A local Linux pass does not establish that the GitHub
workflow or either macOS job has passed.

Physical-key qualification remains a separate manual check. It can leave the
YubiKey connected throughout. Full Freelens GUI qualification and independent
security review remain separate release work.
