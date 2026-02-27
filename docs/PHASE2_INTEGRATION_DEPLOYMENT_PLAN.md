# Phase 2 Plan: Integration Packages + Deployment Cookbooks

This plan turns the Phase 2 roadmap line into concrete, shippable work.

## Goals
- Ship deeper integration packages for core frameworks with enforced sink policy hooks.
- Publish deployment cookbooks that make production rollout repeatable.
- Keep all claims reproducible via tests, CI checks, and runnable examples.

## Deliverable A: Deeper Integration Packages

### Target packages
- `mvar-langchain`
- `mvar-openai`
- `mvar-mcp`

### Package baseline requirements
- Intercept tool execution boundaries and call MVAR sink policy before execution.
- Propagate provenance labels from inbound content to planner/tool outputs.
- Emit deterministic decision trace fields (`policy_hash`, integrity/sink labels, QSEAL fields).
- Include adapter conformance coverage (`conformance/pytest_adapter_harness.py`).
- Include one minimal example app and one attack/benign regression test.

### Acceptance criteria (per package)
- `pytest -q` passes package tests.
- Adapter passes conformance harness.
- Attack path blocks and benign path allows in package-specific examples.
- README quickstart for the package is published.

## Deliverable B: Deployment Cookbooks

### Target cookbooks
- Local Docker deployment (single service)
- Kubernetes deployment (sidecar pattern)
- CI/CD rollout and rollback
- Secrets + key management for QSEAL and runtime policy config
- Observability and incident triage (logs, traces, and alerts)

### Cookbook baseline requirements
- Step-by-step commands with expected outputs.
- Required env vars and security assumptions documented.
- Failure modes and rollback steps included.
- Validation step includes `./scripts/launch-gate.sh` and trilogy check.

### Acceptance criteria (per cookbook)
- Fresh-clone operator can run it in under 30 minutes.
- Validation commands complete successfully.
- Troubleshooting section covers at least top 3 likely failure modes.

## Milestone Sequence

### Milestone 1 (Week 2)
- Ship `mvar-openai` deeper hooks + docs + tests.
- Publish Docker cookbook.

### Milestone 2 (Week 2)
- Ship `mvar-langchain` deeper hooks + docs + tests.
- Publish Kubernetes sidecar cookbook.

### Milestone 3 (Week 3)
- Ship `mvar-mcp` deeper hooks + docs + tests.
- Publish CI/CD + rollback + observability cookbooks.

## Immediate Next Tasks (This Week)
1. Create package skeletons and test matrices for `mvar-openai`, `mvar-langchain`, `mvar-mcp`.
2. Define shared adapter interface contract extensions required for deeper hooks.
3. Add package-specific regression tests mirroring trilogy behavior where applicable.
4. Draft Docker cookbook first, then validate on fresh clone.
5. Track status in one issue per milestone with checklists and links to PRs.

## Definition of Done (Phase 2 line item)
- At least 3 deeper integration packages are released with tests + quickstarts.
- At least 4 deployment cookbooks are published and validated on fresh clone.
- Launch gate and trilogy checks remain green after integration additions.
