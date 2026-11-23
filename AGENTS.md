# Contributor instructions

## Project

An independent personal project, intended for public GitHub use on Linux/macOS.
Company MADR templates, documentation quotas, and sibling-repository checks do
not apply here. Keep this repository usable without the parent workspace.
The primary implementation is the experimental Go/Typage application in `age-app`.
Read [the architecture](docs/ARCHITECTURE.md) before changing authentication.

## Commands

See [development](docs/DEVELOPMENT.md) and `.github/workflows/ci.yml`.
Public instructions use ordinary commands; no workspace-specific wrapper is
required. An agent may use `rtk` when its environment requests it.

## Conventions

Keep browser assets local. Test with synthetic credentials only.
Use Go age and bundled Typage/WebAuthn PRF for the primary implementation.
Keep the historical Python prototype and the `experiments/age-prf` library probe
separate. Never load their state implicitly. Build browser assets before Go.

## Boundaries

### Always

Keep the README and relevant guides accurate when behavior or workflows change.
Add meaningful tests for authentication and security boundary changes.
Distinguish emulated authentication from proof with a physical YubiKey.

### Ask first

Real credential migration is user-operated. Respect the existing prohibition
on assistant access to real kubeconfigs, tokens, SSH keys, and Freelens profiles.

### Never

Read real credentials, reset a YubiKey, or connect to production during tests.
Log WebAuthn payloads, PRF outputs, cookies, or encryption keys.
Commit or push without authorization.

## Docs

The [README](README.md) is the public entry point. Put deeper explanations in
focused guides. Update docs when useful; there are no fixed section or line-count
requirements. Check relative links and verify commands against actual code.

## Gotchas

The browser is for authentication only. Edit configuration in a normal editor.
The compatibility probe is separate from persistent vault enrollment.
Locking the helper cannot revoke tokens already cached by another application.
