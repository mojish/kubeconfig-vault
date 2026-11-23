# Contributor instructions

Kubeconfig Vault is a standalone Go and Typage application for Linux and macOS.
Build browser assets before compiling the binaries in `age-app`. See
[development](docs/DEVELOPMENT.md) for commands and [architecture](docs/ARCHITECTURE.md)
before changing authentication or storage. Keep public instructions usable
outside the parent workspace.

- Keep browser assets local. Use synthetic credentials and loopback APIs in tests.
- Keep docs and meaningful tests in sync with behavior changes. Distinguish virtual
  authentication coverage from physical key and desktop browser tests.
- Do not access real kubeconfigs, vaults, recovery keys, SSH keys, or Freelens
  profiles. Real credential import and migration are user-operated.
- Never log credentials, WebAuthn payloads, cookies, PRF outputs, or encryption keys.
- Commit or push only with authorization.

Edits happen in a normal editor. Lock clears the helper session and preserves
unfinished edits. Clients can keep credentials delivered before locking.
