# What has been tested?

| Environment | Public binary installation | Real kubectl with virtual approval | Real Freelens 2.1.0 desktop with virtual approval | Physical USB YubiKey |
| --- | --- | --- | --- | --- |
| Linux x86-64 | v0.4.2 | Token and embedded client certificate | [Namespace and reconnect](https://github.com/mojish/kubeconfig-vault/actions/runs/45367976618/job/138354586324) | [Token trial](https://github.com/mojish/kubeconfig-vault/blob/v0.4.0/README.md#compatibility) |
| Linux ARM64 | v0.4.2 | [Token and embedded client certificate](https://github.com/mojish/kubeconfig-vault/actions/runs/45354368129/job/138308403582) | [Namespace and reconnect](https://github.com/mojish/kubeconfig-vault/actions/runs/45367976618/job/138354585628) | Pending |
| macOS Apple Silicon | [v0.4.2 first launch](https://github.com/mojish/kubeconfig-vault/actions/runs/45369593186/job/138360110744) | Token and embedded client certificate | [Namespace and reconnect](https://github.com/mojish/kubeconfig-vault/actions/runs/45367976618/job/138354586232) | Pending |
| macOS Intel | [v0.4.2 first launch](https://github.com/mojish/kubeconfig-vault/actions/runs/45369593186/job/138360111115) | Token and embedded client certificate | [Namespace and reconnect](https://github.com/mojish/kubeconfig-vault/actions/runs/45367976618/job/138354586225) | Pending |

**What the desktop rows verify.** On November 24, 2026, all four hosted platforms ran source revision `10251d4`. A real Freelens window displayed a namespace from a disposable API that required the embedded client certificate. Its first connection shared kubectl’s approval and original deadline. After locking the vault and reopening Freelens, the API returned a differently named namespace. The window displayed that new row, and the next kubectl request shared the single fresh approval. The physical-key column records separate hardware evidence. [Desktop trial](https://github.com/mojish/kubeconfig-vault/actions/runs/45367976618) · [Linux token and certificate demonstrations](DEMO.md)

**What the Mac first launch verifies.** On both Mac runners, headless Chrome downloaded the official v0.4.2 archive. The test verified the asset against the GitHub release. Archive Utility preserved quarantine on the executable, macOS reported Gatekeeper assessments enabled, and the first invocation of the newly extracted copy printed the expected version. These jobs had already verified the installer for the same release. A subsequent `spctl --assess --type execute` returned exit code 3 on both machines. These binaries are unnotarized. The volunteer protocol records what a person sees under their Mac’s own policy. [Hosted download results](https://github.com/mojish/kubeconfig-vault/actions/runs/45369593186) · [Mac protocol](MACOS.md)

**What installation and recovery verify.** Each platform installed the v0.4.2 binary from its public tagged and latest URLs. The integration suite also tests lost-key recovery against a disposable API. It removes the first virtual authenticator, stops the old helper and moves the old vault aside. An unrelated offline key is rejected. The correct key restores a backup, and two kubectl requests share one approval from the replacement authenticator. [Public installer results](https://github.com/mojish/kubeconfig-vault/actions/runs/45356682724) · [Release checks](https://github.com/mojish/kubeconfig-vault/actions/runs/45349965079) · [Integration test](../age-app/browser.test.mjs)

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
