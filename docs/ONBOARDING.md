# Source map

Start with the [README](../README.md) for the user flow and
[development guide](DEVELOPMENT.md) to build and test. This is an independent
project; it needs no company workspace or documentation tooling.

## Primary application: `age-app`

| File | Responsibility |
| --- | --- |
| [main.go](../age-app/main.go) | CLI, daemon lifecycle, private Unix IPC, Kubernetes exec protocol |
| [service.go](../age-app/service.go) | Session cache, unlock, import, editing, export |
| [store.go](../age-app/store.go) | age encryption, generations, protected file handling, recovery |
| [config.go](../age-app/config.go) | Kubeconfig validation, public projection, destination binding |
| [browser.go](../age-app/browser.go) | Local HTTP ceremony and private browser launch |
| [web/app.mjs](../age-app/web/app.mjs) | Typage/WebAuthn PRF operations and browser UI |
| [peer_linux.go](../age-app/peer_linux.go), [peer_darwin.go](../age-app/peer_darwin.go) | Native socket peer identity checks |

Browser assets are bundled into the Go executable. Tokens are decrypted in the
native helper; the browser handles file-key operations. See the
[architecture](ARCHITECTURE.md) for the complete trust boundary.

## Tests

Go tests cover native validation, storage, sessions, IPC peer lookup, and HTTP
boundaries. `ui.test.mjs` checks asynchronous page behavior. `browser.test.mjs`
uses virtual FIDO2, isolated Chrome, real kubectl, and a local dummy API.
`physical.test.mjs` is a separate, user-operated hardware qualification with
dummy credentials. Shared Chrome test plumbing lives in `tests/cdp.mjs`.

[CI](guides/continuous-integration.md) covers the age application. Passing native
or virtual-authenticator tests is not evidence of physical-key compatibility.

## Historical components

The root Python files, root `web/`, and most of `tests/` belong to the earlier
[Python prototype](legacy-python.md). The root `./kube-unlock` launcher still
starts it. It has a different vault format and must not become an implicit
migration path into the age application.

`experiments/age-prf` is a [library interoperability experiment](guides/age-prf-experiment.md),
not a second production CLI. It uses its own Go and npm dependencies.
