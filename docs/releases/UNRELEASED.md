# Unreleased

## Security and Enforcement

- Added **Composition Risk Engine** for stateful cumulative risk hardening across a principal/session window.
  - Deterministic thresholds can escalate `ALLOW -> STEP_UP` or harden to `BLOCK` when cumulative risk budget is exceeded.
  - Added regression tests for composition chains and non-counting of blocked actions.

- Added **strict one-time execution token replay defense** (Milestone 1c).
  - Execution-token nonces are consumed on first successful authorization.
  - Replayed tokens are deterministically rejected.
  - Added dedicated replay-defense regression coverage.

- Added **execution-witness binding path** for adapters.
  - `authorize_execution(..., pre_evaluated_decision=...)` validates tool/action/target/provenance/policy-hash binding.
  - Prevents policy re-evaluation drift between planning and execution boundaries.
  - Added regression tests for witness mismatch blocking and composition double-count prevention.

- Expanded **regression gate coverage** in CI.
  - `launch-gate.yml` now includes composition-risk regression tests in addition to existing launch-gate and trilogy checks.

## Compatibility

- **No breaking API changes.**
