# Known Bypasses

Date: 2026-04-21
Status: 1 residual case observed in current corpus run (`0.20%` total bypass rate).

## Residual Case

- Attack: `PRIVESC_003` (authorized_keys persistence)
- Variant type: `redirect_variation`
- Observed behavior: one transformed variant was allowed.

### Notes

- This specific variant transformation mutates shell redirection syntax in a way that is not reliably semantic-preserving for the original command intent.
- The current corpus counts it as a bypass because the transformed command was not blocked, even though transformation fidelity is questionable.

## Next Hardening Step

Add a regression fixture that distinguishes:

1. semantic-preserving evasions (must be blocked), and
2. semantics-breaking rewrites (should be excluded from bypass scoring).

This avoids over-crediting invalid evasions while retaining strict enforcement against real attacker-preserving transformations.

