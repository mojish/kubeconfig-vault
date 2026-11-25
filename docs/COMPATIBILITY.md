# What has been tested?

The public **v0.5.1** installer passed on all four platforms on November 24, 2026. Each fresh runner downloaded the matching archive, installed from both the tagged and latest URLs, and checked the executable. The desktop runs used Freelens 2.1.0 and a virtual USB security key in Chrome. [Public release](https://github.com/mojish/kubeconfig-vault/releases/tag/v0.5.1) · [Native installation results](https://github.com/mojish/kubeconfig-vault/actions/runs/45416724761)

| Native platform | v0.5.1 public install | v0.5.1 kubectl and Freelens | Physical USB YubiKey |
| --- | --- | --- | --- |
| Ubuntu 24.04 x86-64 | [Passed](https://github.com/mojish/kubeconfig-vault/actions/runs/45416724761/job/138524842399) | [Chrome 157, kubectl 1.37.2](https://github.com/mojish/kubeconfig-vault/actions/runs/45417266390/job/138526792743) · [expiry trial](https://github.com/mojish/kubeconfig-vault/actions/runs/45416696106/job/138524747372) | [v0.5.1 kubectl and Freelens certificate trials](#physical-certificate-trial-on-ubuntu) · [Earlier token trial](https://github.com/mojish/kubeconfig-vault/blob/v0.4.0/README.md#compatibility) |
| Ubuntu 24.04 ARM64 | [Passed](https://github.com/mojish/kubeconfig-vault/actions/runs/45416724761/job/138524842368) | [Chrome 158, kubectl 1.37.2](https://github.com/mojish/kubeconfig-vault/actions/runs/45417266390/job/138526793030) · [expiry trial](https://github.com/mojish/kubeconfig-vault/actions/runs/45416696106/job/138524746741) | Pending |
| macOS 15 Intel | [Passed](https://github.com/mojish/kubeconfig-vault/actions/runs/45416724761/job/138524842207) | [Chrome 151, kubectl 1.36.4](https://github.com/mojish/kubeconfig-vault/actions/runs/45417266390/job/138526793268) · [expiry trial](https://github.com/mojish/kubeconfig-vault/actions/runs/45416696106/job/138524747771) | Pending |
| macOS 15 Apple Silicon | [Passed](https://github.com/mojish/kubeconfig-vault/actions/runs/45416724761/job/138524841734) | [Chrome 158, kubectl 1.37.2](https://github.com/mojish/kubeconfig-vault/actions/runs/45417266390/job/138526793384) · [expiry trial](https://github.com/mojish/kubeconfig-vault/actions/runs/45416696106/job/138524747341) | Pending |

**What the clients did.** Real kubectl requests exercised both bearer tokens and embedded client certificates. The Freelens test required mutual TLS. It opened the linked kubeconfig, shared kubectl’s existing approval and displayed a namespace returned by the API. After locking and reopening the app, the API returned a new namespace name. Seeing that new name in the window confirmed a fresh authenticated read. [Captioned Linux demonstrations](DEMO.md)

**One hour with Freelens open.** All four v0.5.1 desktops stayed open through a real session expiry. Each runner made six fresh kubectl requests at 50, 40, 30, 20, 10 and 1 minute before expiry. Every request kept the original deadline. Two requests after expiry shared one new approval, and the same Freelens window displayed a new namespace from the mutual-TLS API. A separate quit-and-reopen check then required one approval that kubectl reused. [Four native expiry results](https://github.com/mojish/kubeconfig-vault/actions/runs/45416696106)

**First launch on macOS.** On November 25, Chrome again downloaded both v0.5.1 Mac archives and Archive Utility preserved the quarantine attribute on the executable. With Gatekeeper assessments enabled, the first invocation printed the expected version on both hosted Macs. A separate `spctl --assess --type execute` returned exit code 3 on both. The binaries are unnotarized, and managed Mac policies can differ. [Apple Silicon observation](https://github.com/mojish/kubeconfig-vault/actions/runs/45577527206/job/139079048923) · [Intel observation](https://github.com/mojish/kubeconfig-vault/actions/runs/45577527206/job/139079048968) · [Mac trial protocol](MACOS.md)

**Occasional desktop test timeouts.** One hosted v0.5.0 Intel Mac reached the renderer and stalled while loading the catalog. A separate Linux v0.5.1 run stalled on the first debugging request. Subsequent desktop runs passed on all four platforms. The causes remain open. The harness now distinguishes these stages and reports the last completed step, elapsed time, first unanswered debugging method when known, child-process state, and whether kubectl had already reached the fixture. If you observe a stall, include that short diagnostic in the existing issue. [Original observations and investigation](https://github.com/mojish/kubeconfig-vault/issues/35) · [Four-platform repeat with the release binary](https://github.com/mojish/kubeconfig-vault/actions/runs/45575671548)

**Replacing a lost key.** The recovery test removes the original virtual authenticator, moves the old vault aside and removes the plaintext export. An unrelated recovery key is rejected. Restoring the encrypted backup with the correct offline key allows enrollment of a replacement authenticator. A valid bearer token and an embedded certificate then reach the test API after a single unlock. A third, expired token is refused before reaching the API. [Four packaged v0.5.1 recovery runs](https://github.com/mojish/kubeconfig-vault/actions/runs/45414834452)

## Physical certificate trial on Ubuntu

On November 25, 2026, a maintainer tested the published v0.5.1 Linux x86-64 binary (`f8e41c4`) with the trial scripts at `6956102`, Ubuntu 24.04.5, Chrome 158.0.8127.36, kubectl 1.36.6, and a physical USB YubiKey. The key stayed connected. The client used a disposable embedded certificate and private key against a loopback API that required mutual TLS. [Pinned trial procedure](TRIALS.md#choose-a-trial)

- During preflight, kubectl read the test namespace and the server rejected a client without valid credentials.
- After enrollment, a fresh kubectl process triggered a browser approval and reached the API. Two more processes reused the session without opening another page or extending its deadline.
- After locking the helper, offline recovery produced a kubeconfig that reached the same API. The helper stayed locked and recovery opened no browser page.

A second maintainer run used the same published binary, Ubuntu and kubectl versions, a private Wayland desktop profile, and Freelens 2.1.0. After physical approval, Freelens displayed `vault-test` from the mutual-TLS API and two fresh kubectl processes reused its approval. The driver then locked the helper and reopened Freelens. A single fresh approval displayed `vault-test-reconnected`, and kubectl reused the new session. Offline recovery reached the API with the helper locked. The key stayed connected for both runs. [Linux desktop test source](https://github.com/mojish/kubeconfig-vault/blob/0fa11ccf687f0b135ef825c5772531f946d70bf7/age-app/physical.test.mjs)

## Most valuable next trials

We’re looking for an independent first-time setup, a physical Mac desktop trial, and recovery using a second physical key. Choose one in the [pinned trial kit](TRIALS.md). It supplies a disposable API and asks you to record where you first needed help. A blocked attempt is useful too.

| Trial | How to do it with disposable data | What counts as a pass |
| --- | --- | --- |
| Independent repeat with a physical YubiKey and client certificate | From a checkout, follow the [certificate preflight and hardware steps](DEVELOPMENT.md#test-with-a-physical-yubikey). Leave the key connected. | Plain kubectl works first, the control with invalid credentials fails, and both protected and recovered configs reach the mutual-TLS API. |
| Physical Mac key and first-launch experience | Run the [Mac protocol](MACOS.md) on each CPU family. Record quarantine and first launch before running the desktop workflow. | Record Gatekeeper's decision as its own result. For the GUI, record the authenticated namespace on the first connection and again after reconnect. |
| Recover the latest save | In a disposable test account, protect a test config, edit a harmless namespace using `kubeconfig-vault edit`, save and make a fresh backup. In a clean directory run `recover BACKUP.age --check`, then `recover BACKUP.age --out recovered` using the saved offline key. Use the [recovery guide](README.md#choose-a-recovery-path). | `kubectl --kubeconfig recovered config view --minify -o 'jsonpath={.contexts[0].context.namespace}'` shows the edit and a read-only API request works. Separately, `config unlink` on the linked test file restores the original from setup. |

Record one row per attempt, including a blocked or inconclusive result. Use the [compatibility issue form](https://github.com/mojish/kubeconfig-vault/issues/new?template=compatibility.yml), or keep a private report using the line below.

```text
Application tag and commit / test-source commit if used / OS and CPU / browser / client and version / authenticator model and connection / token or certificate / scenario / passed, blocked or inconclusive / first confusing step
```

A stage name and a short redacted error are enough. Leave out credentials, device serial numbers, kubeconfigs, browser URLs and full logs. The independent review has a [separate scope](../SECURITY.md#independent-review-before-v1).

## How trial results guide changes

Count attempts alongside completions. For an end-to-end pass, look for setup, an authenticated request, lock and a fresh approval. Track installation-only checks separately. Two independent reports that stop at the same step are a good reason to fix that step first. Treat a damaged config, credential disclosure or failed verified recovery as a blocker for the affected workflow.

A reproducible Gatekeeper block would justify work on signing and notarization. Repeated installer friction would justify assessing Homebrew. For Krew, first check that the absolute exec path survives updates and that uninstall leaves a usable recovery path. A request for another client, such as Helm or K9s, starts with a trial of that client.
