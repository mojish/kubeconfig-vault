# What has been tested?

The public **v0.5.0** installer passed on all four targets below on November 24, 2026. Each fresh runner downloaded and installed the tagged release and the `latest` release, then checked the installed executable. All desktop results in the table used Freelens 2.1.0 and a virtual USB security key in Chrome. The last column records the separate physical-device evidence. [Public release](https://github.com/mojish/kubeconfig-vault/releases/tag/v0.5.0) · [Four native installation results](https://github.com/mojish/kubeconfig-vault/actions/runs/45388988341)

| Native platform | Public install | kubectl and Freelens | Physical USB YubiKey |
| --- | --- | --- | --- |
| Ubuntu 24.04 x86-64 | [Passed](https://github.com/mojish/kubeconfig-vault/actions/runs/45388988341/job/138427370045) | [Chrome 157, kubectl 1.37.2](https://github.com/mojish/kubeconfig-vault/actions/runs/45392562262/job/138439819185) | [Earlier Linux token trial](https://github.com/mojish/kubeconfig-vault/blob/v0.4.0/README.md#compatibility) |
| Ubuntu 24.04 ARM64 | [Passed](https://github.com/mojish/kubeconfig-vault/actions/runs/45388988341/job/138427370292) | [Chrome 158, kubectl 1.37.2](https://github.com/mojish/kubeconfig-vault/actions/runs/45392562262/job/138439819684) | Pending |
| macOS 15 Intel | [Passed](https://github.com/mojish/kubeconfig-vault/actions/runs/45388988341/job/138427370594) | [Chrome 151, kubectl 1.36.4](https://github.com/mojish/kubeconfig-vault/actions/runs/45392562262/job/138439819692) | Pending |
| macOS 15 Apple Silicon | [Passed](https://github.com/mojish/kubeconfig-vault/actions/runs/45388988341/job/138427370649) | [Desktop trial](https://github.com/mojish/kubeconfig-vault/actions/runs/45382524965/job/138404935879) | Pending |

**What the clients did.** Real kubectl requests exercised both bearer tokens and embedded client certificates. The Freelens test required mutual TLS. It opened the linked kubeconfig, shared kubectl’s existing approval and displayed a namespace returned by the API. After locking and reopening the app, the API returned a new namespace name. Seeing that new name in the window confirmed a fresh authenticated read. [Captioned Linux demonstrations](DEMO.md)

**One hour with Freelens open.** Six fresh kubectl requests succeeded at 50, 40, 30, 20, 10 and 1 minute before expiry. They kept the original deadline. After expiry, two requests shared one new approval and the same Freelens window displayed a new authenticated namespace. The completed runs used the published v0.5.0 binary and a virtual security key. [Linux x86-64](https://github.com/mojish/kubeconfig-vault/actions/runs/45388979608/job/138427337348) · [Linux ARM64](https://github.com/mojish/kubeconfig-vault/actions/runs/45388979608/job/138427337517) · [Intel Mac](https://github.com/mojish/kubeconfig-vault/actions/runs/45388979608/job/138427337325)

**First launch on macOS.** Chrome downloaded each official Mac archive. Archive Utility preserved the quarantine attribute on the executable. Gatekeeper assessments were enabled, and the first invocation printed the expected version on both hosted Macs. A separate `spctl --assess --type execute` returned exit code 3 on both. The binaries are unnotarized, and a managed Mac can apply a different policy. [Mac trial protocol](MACOS.md)

**Replacing a lost key.** The recovery test removes the original virtual authenticator, moves the old vault aside and removes the plaintext export. An unrelated recovery key is rejected. Restoring the encrypted backup with the correct offline key allows enrollment of a replacement authenticator. A valid bearer token and an embedded certificate then reach the test API after a single unlock. A third, expired token is refused before reaching the API. [Recovery regression and CI](https://github.com/mojish/kubeconfig-vault/pull/25)

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
