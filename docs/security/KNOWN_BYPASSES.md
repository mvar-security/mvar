# Known Bypasses

Date: 2026-04-22
Status: Residual cases are now tracked under dual metrics (`raw` + `semantic-preserving`).

## Residual Case

- Attack: `PRIVESC_003` (authorized_keys persistence)
- Variant type: `redirect_variation`
- Observed behavior: one transformed variant was allowed.

### Notes

- This specific variant transformation mutates shell redirection syntax in a way that is not reliably semantic-preserving for the original command intent.
- The current corpus counts it as a bypass because the transformed command was not blocked, even though transformation fidelity is questionable.

## Current Handling

Implemented in harness + CI:

1. semantic-preserving evasions (must be blocked), and
2. semantics-breaking rewrites (tracked, but excluded from semantic bypass rate).

This prevents inflating bypass metrics with transformations that do not preserve attacker intent.
