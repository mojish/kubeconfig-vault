# What has been tested?

The public **v0.5.1** installer passed on all four platforms on November 24, 2026. Each fresh runner downloaded the matching archive, installed from both the tagged and latest URLs, and checked the executable. The desktop runs used Freelens 2.1.0 and a virtual USB security key in Chrome. [Public release](https://github.com/mojish/kubeconfig-vault/releases/tag/v0.5.1) · [Native installation results](https://github.com/mojish/kubeconfig-vault/actions/runs/45416724761)

| Native platform | v0.5.1 public install | v0.5.1 kubectl and Freelens | Physical USB YubiKey |
| --- | --- | --- | --- |
| Ubuntu 24.04 x86-64 | [Passed](https://github.com/mojish/kubeconfig-vault/actions/runs/45416724761/job/138524842399) | [Chrome 157, kubectl 1.37.2](https://github.com/mojish/kubeconfig-vault/actions/runs/45417266390/job/138526792743) · [expiry trial](https://github.com/mojish/kubeconfig-vault/actions/runs/45416696106/job/138524747372) | [Earlier Linux token trial](https://github.com/mojish/kubeconfig-vault/blob/v0.4.0/README.md#compatibility) |
| Ubuntu 24.04 ARM64 | [Passed](https://github.com/mojish/kubeconfig-vault/actions/runs/45416724761/job/138524842368) | [Chrome 158, kubectl 1.37.2](https://github.com/mojish/kubeconfig-vault/actions/runs/45417266390/job/138526793030) · [expiry trial](https://github.com/mojish/kubeconfig-vault/actions/runs/45416696106/job/138524746741) | Pending |
| macOS 15 Intel | [Passed](https://github.com/mojish/kubeconfig-vault/actions/runs/45416724761/job/138524842207) | [Chrome 151, kubectl 1.36.4](https://github.com/mojish/kubeconfig-vault/actions/runs/45417266390/job/138526793268) · [expiry trial](https://github.com/mojish/kubeconfig-vault/actions/runs/45416696106/job/138524747771) | Pending |
| macOS 15 Apple Silicon | [Passed](https://github.com/mojish/kubeconfig-vault/actions/runs/45416724761/job/138524841734) | [Chrome 158, kubectl 1.37.2](https://github.com/mojish/kubeconfig-vault/actions/runs/45417266390/job/138526793384) · [expiry trial](https://github.com/mojish/kubeconfig-vault/actions/runs/45416696106/job/138524747341) | Pending |

**What the clients did.** Real kubectl requests exercised both bearer tokens and embedded client certificates. The Freelens test required mutual TLS. It opened the linked kubeconfig, shared kubectl’s existing approval and displayed a namespace returned by the API. After locking and reopening the app, the API returned a new namespace name. Seeing that new name in the window confirmed a fresh authenticated read. [Captioned Linux demonstrations](DEMO.md)

**One hour with Freelens open.** The expiry trials linked in the table keep the app open and run fresh kubectl requests at 50, 40, 30, 20, 10 and 1 minute before the deadline. To pass, every request must preserve the original deadline, two requests after expiry must share one new approval, and the same window must display a new authenticated namespace. The preceding v0.5.0 release completed this sequence on all four platforms. [Earlier full-hour results](https://github.com/mojish/kubeconfig-vault/actions/runs/45388979608)

**First launch on macOS.** Chrome downloaded both v0.5.1 Mac archives and Archive Utility preserved the quarantine attribute on the executable. With Gatekeeper assessments enabled, the first invocation printed the expected version on both hosted Macs. A separate `spctl --assess --type execute` returned exit code 3 on both. The binaries are unnotarized, and managed Mac policies can differ. [Apple Silicon observation](https://github.com/mojish/kubeconfig-vault/actions/runs/45416724761/job/138524841734) · [Intel observation](https://github.com/mojish/kubeconfig-vault/actions/runs/45416724761/job/138524842207) · [Mac trial protocol](MACOS.md)

**An intermittent Intel desktop result.** A separate v0.5.0 hosted run completed its kubectl checks, then timed out waiting for the Freelens catalog. The log identifies a renderer debugging command that did not respond before the navigation deadline. The cause is still open. [Intel trial log](https://github.com/mojish/kubeconfig-vault/actions/runs/45402241683/job/138513828007)

**Replacing a lost key.** The recovery test removes the original virtual authenticator, moves the old vault aside and removes the plaintext export. An unrelated recovery key is rejected. Restoring the encrypted backup with the correct offline key allows enrollment of a replacement authenticator. A valid bearer token and an embedded certificate then reach the test API after a single unlock. A third, expired token is refused before reaching the API. [Four packaged v0.5.1 recovery runs](https://github.com/mojish/kubeconfig-vault/actions/runs/45414834452)

## Most valuable next trials

| Trial | How to do it with disposable data | What counts as a pass |
| --- | --- | --- |
| Physical YubiKey and a client certificate | From a checkout, follow the [certificate preflight and hardware steps](DEVELOPMENT.md#test-with-a-physical-yubikey). Leave the key connected. | Plain kubectl works first, the control with invalid credentials fails, and both protected and recovered configs reach the mutual-TLS API. |
| Physical Mac key and first-launch experience | Run the [Mac protocol](MACOS.md) on each CPU family. Record quarantine and first launch before running the desktop workflow. | Record Gatekeeper's decision as its own result. For the GUI, record the authenticated namespace on the first connection and again after reconnect. |
| Recover the latest save | In a disposable test account, protect a test config, edit a harmless namespace using `kubeconfig-vault edit`, save and make a fresh backup. In a clean directory run `recover BACKUP.age --check`, then `recover BACKUP.age --out recovered` using the saved offline key. Use the [recovery guide](README.md#choose-a-recovery-path). | `kubectl --kubeconfig recovered config view --minify -o 'jsonpath={.contexts[0].context.namespace}'` shows the edit and a read-only API request works. Separately, `config unlink` on the linked test file restores the original from setup. |

Record one row per attempt, including a blocked or inconclusive result. Use the [compatibility issue form](https://github.com/mojish/kubeconfig-vault/issues/new?template=compatibility.yml), or keep a private report using the line below.

```text
Release / OS and CPU / browser / client and version / authenticator model and connection / token or certificate / scenario / passed, blocked or inconclusive / first confusing step
```

A stage name and a short redacted error are enough. Leave out credentials, device serial numbers, kubeconfigs, browser URLs and full logs. The independent review has a [separate scope](../SECURITY.md#independent-review-before-v1).

## How trial results guide changes

Count attempts alongside completions. For an end-to-end pass, look for setup, an authenticated request, lock and a fresh approval. Track installation-only checks separately. Two independent reports that stop at the same step are a good reason to fix that step first. Treat a damaged config, credential disclosure or failed verified recovery as a blocker for the affected workflow.

A reproducible Gatekeeper block would justify work on signing and notarization. Repeated installer friction would justify assessing Homebrew. For Krew, first check that the absolute exec path survives updates and that uninstall leaves a usable recovery path. A request for another client, such as Helm or K9s, starts with a trial of that client.
