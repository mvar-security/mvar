# Changelog

This root changelog is the canonical release summary.
Detailed release notes live under `docs/releases/*`.

## v1.4.0

### What’s New
- Verified execution contracts required for privileged sink calls (`bash.exec`, `http.post`).
- Invocation-hash binding and strict egress controls were finalized in the shipped runtime path.

### Security Impact
- Eliminates decision/execution drift classes for contracted sinks and tightens strict-mode egress posture.

### Validation Snapshot
- Launch gate: PASS · Attack corpus: 50/50 blocked · Full suite: 294 passing.
- Details: [docs/releases/v1.4.0.md](docs/releases/v1.4.0.md)

## v1.3.1

### What’s New
- Strict-profile hardening and release-line hygiene updates were consolidated between v1.3.0 and v1.4.0.
- Focus remained on preserving governed enforcement continuity while tightening defaults.

### Security Impact
- Strengthened strict-mode operational posture ahead of execution-contract enforcement landing in v1.4.0.

### Validation Snapshot
- Launch-gate and attack-corpus validation remained release-blocking in this line.
- Details: [docs/releases/UNRELEASED.md](docs/releases/UNRELEASED.md)

## v1.3.0

### What’s New
- Strict mode enforced Ed25519-only verification.
- Signed policy bundles became mandatory at strict-profile startup.

### Security Impact
- Removed strict-mode HMAC fallback and enforced authenticated policy roots.

### Validation Snapshot
- Launch gate: PASS · Attack corpus: 50/50 blocked · Red-team gate: 7/7 passing.
- Details: [docs/releases/v1.3.0.md](docs/releases/v1.3.0.md)

## v1.2.3

### What’s New
- Stabilized pre-v1.3 release line while maintaining deterministic sink-enforcement behavior.
- Prepared the transition into strict-profile hardening work.

### Security Impact
- Preserved enforcement baseline with CI-governed validation before strict-profile upgrades.

### Validation Snapshot
- Launch-gate and corpus validation remained green for the release line.
- Details: [docs/releases/v1.2.2.md](docs/releases/v1.2.2.md)
