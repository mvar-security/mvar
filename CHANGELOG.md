# Changelog

All notable changes to MVAR are documented here.
Detailed release notes live under `docs/releases/*`.

## [1.4.0] - 2026-03-09 — Verified Execution Contracts
- **What’s New:** Required verified execution contracts for privileged sink calls with invocation-hash binding at enforcement time.
- **Security Impact:** Eliminates decision/execution drift for contracted sinks and hardens replay/mutation resistance at the sink boundary.
- **Validation Snapshot:** Launch gate PASS · Attack corpus 50/50 blocked · Full suite 294 passing.
- **Details:** [docs/releases/v1.4.0.md](docs/releases/v1.4.0.md)

## [1.3.1] - 2026-03-09 — HTTP Egress Hardening
- **What’s New:** Added strict-profile default-deny outbound HTTP egress with explicit allowlist control.
- **Security Impact:** Blocks non-allowlisted egress in strict profile and fails closed when strict allowlist requirements are missing.
- **Validation Snapshot:** Launch-gate and attack-corpus checks remained release-blocking for this line.
- **Details:** [docs/releases/UNRELEASED.md](docs/releases/UNRELEASED.md)

## [1.3.0] - 2026-03-08 — Strict-Mode Enterprise Hardening
- **What’s New:** Enforced Ed25519-only strict mode and required signed policy bundles at strict startup.
- **Security Impact:** Removed strict-mode HMAC fallback and anchored strict decisions to authenticated policy roots.
- **Validation Snapshot:** Launch gate PASS · Attack corpus 50/50 blocked · Full suite 293 passing.
- **Details:** [docs/releases/v1.3.0.md](docs/releases/v1.3.0.md)

## [1.2.3] - 2026-03-08 — README Clarity + Stable Launch Gate
- **What’s New:** Tightened conversion-first README flow while preserving reproducible proof and validation paths.
- **Security Impact:** Kept deterministic sink-enforcement posture intact during documentation and launch-surface refactor.
- **Validation Snapshot:** Launch gate PASS with corpus and CI checks green on the release line.
- **Details:** [docs/releases/v1.2.2.md](docs/releases/v1.2.2.md)
