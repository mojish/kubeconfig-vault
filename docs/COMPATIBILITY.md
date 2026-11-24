# What has been tested?

A release archive, a successful API request and a physical-key test answer different questions. This table records the evidence for each separately. A dash means the linked evidence does not establish that result.

| Environment | Archive installation | Credential delivery to a disposable API | Physical key or desktop |
| --- | --- | --- | --- |
| Linux x86-64 | v0.4.2 native release job and post-publication download | Chrome virtual USB authenticator and real kubectl, with both an inline token and an embedded TLS certificate/key pair. The certificate also worked after offline recovery. | Physical YubiKey with a token by v0.4.0. Freelens 2.1.0 desktop with a token and, in a separate v0.4.2 trial, an [embedded client key and certificate](DEMO.md#freelens-with-a-client-certificate). Both desktop demonstrations used virtual approval. |
| Linux ARM64 | v0.4.2 native install, version and compatibility-link checks | [Native source-build trial](https://github.com/mojish/kubeconfig-vault/actions/runs/45354368129/job/138308403582) with Chrome 158.0.8127.88, virtual USB and kubectl v1.37.2. A token and a client certificate each authenticated, including mutual TLS after offline recovery. | — |
| macOS Apple Silicon | v0.4.2 native release job | Packaged CLI, Chrome virtual authenticator and real kubectl, with token and certificate credentials | Physical USB approval, Freelens desktop and first launch of a quarantined download await a Mac trial. |
| macOS Intel | v0.4.2 native release job | Same packaged test on the Intel runner | The same three observations await an Intel Mac trial. |

The tagged and latest installer downloads for v0.4.2 were each verified on all four native platforms. The baseline also includes separate hardware and desktop trials. [Four-platform public installer results](https://github.com/mojish/kubeconfig-vault/actions/runs/45356682724) · [v0.4.2 release run](https://github.com/mojish/kubeconfig-vault/actions/runs/45349965079) · [Earlier Linux trials](https://github.com/mojish/kubeconfig-vault/blob/v0.4.0/README.md#compatibility)

The [integration test](../age-app/browser.test.mjs) exercises bearer authentication and mutual TLS separately. The API accepts the generated certificate only with proof of possession of the matching private key.

On November 24, 2026, the v0.4.1 source build also ran with a virtual USB authenticator on Linux x86-64. Chrome 158 and kubectl v1.36.6 established one session. Freelens 2.1.0 displayed the authenticated `vault-test` namespace with the same expiration and no second approval. A separate run checked the proxy's first refresh after lock. The [captioned walkthrough and transcript](DEMO.md) show both observations.

The v0.4.2 Linux x86-64 candidate was also tested after installation from its archive. Real kubectl authenticated with both credential types, the Freelens proxy requested fresh approval after its cached credential deadline, and the recovered certificate authenticated to the mutual-TLS endpoint. The desktop recording above uses the v0.4.1 build.

A subsequent Linux x86-64 test used the published v0.4.2 binary with a new virtual authenticator. With the original helper stopped, its state path unavailable and its authenticator removed, an unrelated recovery key failed before enrollment. The correct offline key restored the edited backup into fresh state. Two real kubectl requests reused one new approval from the replacement authenticator.

## Most valuable next trials

| Trial | How to do it with disposable data | What counts as a pass |
| --- | --- | --- |
| Physical YubiKey and a client certificate | From a checkout, follow the [certificate preflight and hardware steps](DEVELOPMENT.md#test-with-a-physical-yubikey). Leave the key connected. | Plain kubectl works first, the control with invalid credentials fails, and both protected and recovered configs reach the mutual-TLS API. |
| macOS download and desktop | Run the [Mac protocol](MACOS.md) on each CPU family. Record quarantine and first launch before running the desktop workflow. | Record Gatekeeper's decision as its own result. For the GUI, record the authenticated namespace on the first connection and again after reconnect. |
| Recover the latest save | In a disposable test account, protect a test config, edit a harmless namespace using `kubeconfig-vault edit`, save and make a fresh backup. In a clean directory run `recover BACKUP.age --check`, then `recover BACKUP.age --out recovered` using the saved offline key. Use the [recovery guide](README.md#choose-a-recovery-path). | `kubectl --kubeconfig recovered config view --minify -o 'jsonpath={.contexts[0].context.namespace}'` shows the edit and a read-only API request works. Separately, `config unlink` on the linked test file restores the original from setup. |

Record one row per attempt, including a blocked or inconclusive result. Use the [compatibility issue form](https://github.com/mojish/kubeconfig-vault/issues/new?template=compatibility.yml), or keep a private report using the line below.

```text
Release / OS and CPU / browser / client and version / authenticator model and connection / token or certificate / scenario / passed, blocked or inconclusive / first confusing step
```

A stage name and a short redacted error are enough. Leave out credentials, device serial numbers, kubeconfigs, browser URLs and full logs. The independent review has a [separate scope](../SECURITY.md#independent-review-before-v1).

## How trial results guide changes

Count attempts alongside completions. For an end-to-end pass, look for setup, an authenticated request, lock and a fresh approval. Track installation-only checks separately. Two independent reports that stop at the same step are a good reason to fix that step first. Treat a damaged config, credential disclosure or failed verified recovery as a blocker for the affected workflow.

A reproducible Gatekeeper block would justify work on signing and notarization. Repeated installer friction would justify assessing Homebrew. For Krew, first check that the absolute exec path survives updates and that uninstall leaves a usable recovery path. A request for another client, such as Helm or K9s, starts with a trial of that client.
