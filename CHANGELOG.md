# Changelog

All notable changes to MVAR are documented in `docs/releases/`.

## v1.4.0

- Verified execution contracts for privileged sink calls (`bash.exec`, `http.post`):
  - invocation hash binding between authorization and exact runtime invocation
  - fail-closed block behavior for missing/invalid/mutated/replayed contracts
- Strict-profile HTTP egress hardening:
  - default deny unless explicitly allowlisted
  - actionable failure path when allowlist is missing in strict mode

Full release notes: [docs/releases/v1.4.0.md](docs/releases/v1.4.0.md)

## v1.3.0

- Strict-mode enterprise hardening:
  - Ed25519-only enforcement in strict profile
  - Mandatory signed policy bundles in strict profile
  - Explicit fail-closed startup errors for missing/invalid strict prerequisites

Full release notes: [docs/releases/v1.3.0.md](docs/releases/v1.3.0.md)

## Previous releases

- [v1.2.2](docs/releases/v1.2.2.md)
- [v1.2.0](docs/releases/v1.2.0.md)
- [v1.1.0](docs/releases/v1.1.0.md)
- [v1.0.4](docs/releases/v1.0.4.md)
