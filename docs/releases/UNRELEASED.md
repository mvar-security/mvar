# Unreleased

## Security and Enforcement

- Added **Composition Risk Engine** for stateful cumulative risk hardening across a principal/session window.
  - Deterministic thresholds can escalate `ALLOW -> STEP_UP` or harden to `BLOCK` when cumulative risk budget is exceeded.
  - Added regression tests for composition chains and non-counting of blocked actions.

- Added **strict one-time execution token replay defense** (Milestone 1c).
  - Execution-token nonces are consumed on first successful authorization.
  - Replayed tokens are deterministically rejected.
  - Added dedicated replay-defense regression coverage.
  - Added optional persisted nonce store (`MVAR_EXECUTION_TOKEN_NONCE_PERSIST=1`) so replay protection survives policy/runtime restart.
  - Nonce-consumption events are now signed and appended to the decision ledger chain for tamper-evident replay forensics.

- Added **execution-witness binding path** for adapters.
  - `authorize_execution(..., pre_evaluated_decision=...)` validates tool/action/target/provenance/policy-hash binding.
  - Prevents policy re-evaluation drift between planning and execution boundaries.
  - Added regression tests for witness mismatch blocking and composition double-count prevention.

- Added **deterministic declassification + scoped memory write gates** (Milestone 2a).
  - `memory.write` now enforces scope widening rules (`session -> user -> org`).
  - Sensitive/secret cross-scope writes require a signed declassify token.
  - Added one-time declassify token replay rejection.

- Added **signed policy bundle startup verification gate** (Milestone 2b).
  - Runtime can require a signed canonical policy bundle at startup (`MVAR_REQUIRE_SIGNED_POLICY_BUNDLE=1`).
  - Startup blocks if bundle is missing, signature-invalid, or hash/payload mismatched.
  - Added bundle generation helper: `scripts/generate_signed_policy_bundle.py`.

- Expanded **regression gate coverage** in CI.
  - `launch-gate.yml` now includes composition-risk regression tests in addition to existing launch-gate and trilogy checks.
  - OpenAI Docker smoke now asserts persisted nonce replay blocking across container restart.
  - Added declassification memory-scope regression tests.
  - Added signed policy-bundle startup regression tests.

## Compatibility

- **No breaking API changes.**
