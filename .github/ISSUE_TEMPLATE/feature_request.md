---
name: Feature Request
about: Suggest an enhancement for MVAR
title: "[FEATURE] "
labels: enhancement
assignees: ''
---

## Problem Statement

What problem are you solving?

## Proposed Change

Describe the feature and expected behavior.

## Security Boundary Impact

Does this touch any of the following?

- [ ] Sink enforcement
- [ ] Execution token boundary
- [ ] Principal isolation
- [ ] Adapter conformance
- [ ] No boundary impact

If yes, explain expected invariant preservation.

## Backward Compatibility

- [ ] No breaking changes
- [ ] Potential breaking changes (describe)

## Validation Plan

How should maintainers validate this?

```bash
# Suggested checks
pytest -q
python -m demo.extreme_attack_suite_50
./scripts/launch-gate.sh
```

## Would you like to implement this?

- [ ] Yes, I can open a PR
- [ ] I can help test
- [ ] Suggestion only
