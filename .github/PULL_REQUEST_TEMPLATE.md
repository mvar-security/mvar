## Summary

- What changed:
- Why this change is needed:

## Scope

- [ ] `mvar-core/`
- [ ] `mvar_adapters/`
- [ ] `demo/`
- [ ] `tests/`
- [ ] Docs
- [ ] CI/workflows
- [ ] Other:

## Validation (Required)

Run and paste exact outputs for the commands relevant to your change.

```bash
# Baseline
pytest -q
python -m demo.extreme_attack_suite_50

# Full gate
./scripts/launch-gate.sh
```

Results:
- `pytest -q`:
- `python -m demo.extreme_attack_suite_50`:
- `./scripts/launch-gate.sh`:

## Security Invariants (Required)

Confirm this PR preserves MVAR security boundaries:

- [ ] Sink enforcement: no direct tool execution bypass
- [ ] Execution token boundary: no bypass when required
- [ ] Principal isolation: trust/override state remains principal-bound
- [ ] Adapter conformance: integration path still respects contract

## API / Behavior Impact

- [ ] No API changes
- [ ] Backward-compatible API changes
- [ ] Breaking changes (describe)

Behavior changes:

## Documentation

- [ ] README/docs updated if behavior changed
- [ ] Threat model updated if assumptions changed

## Security Checklist

- [ ] No secrets/tokens/keys committed
- [ ] No hardcoded credentials
- [ ] Fail-closed behavior preserved for critical paths

## Related Issues

- Closes #
- Related #

## Follow-Up

- [ ] None
- [ ] Follow-up issue required (link):
