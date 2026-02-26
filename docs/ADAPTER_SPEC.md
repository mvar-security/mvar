# MVAR Adapter Contract (Strict Conformance)

Status: Launch baseline contract

This contract defines the minimum integration boundary for any framework adapter (LangChain, OpenAI Agents, MCP tools, etc.) to be considered MVAR-conformant.

## Security objective

Adapters MUST make direct tool execution impossible without passing through MVAR policy evaluation and execution-token authorization.

## Required adapter behavior

1. No direct sink execution
- Tool/process/network/file execution MUST NOT be callable from adapter codepaths without MVAR authorization.
- All sink calls MUST route through a single enforcement wrapper.

2. Provenance before policy
- Adapter MUST create/lookup a provenance node before sink evaluation.
- For untrusted external inputs, provenance integrity MUST be `UNTRUSTED`.

3. Deterministic policy evaluation
- Adapter MUST call:
  - `policy.evaluate(...)` for preflight decisions/logging, OR
  - `policy.authorize_execution(...)` for enforcement path.
- For executable sinks, the effective enforcement call MUST be `authorize_execution(...)`.

4. Execution-token boundary
- When `MVAR_REQUIRE_EXECUTION_TOKEN=1`, adapter MUST pass the returned token into authorization.
- If token is missing/invalid, execution MUST be blocked (fail-closed).

5. Principal isolation
- Adapter MUST pass explicit principal identity into MVAR context (`MVAR_PRINCIPAL_ID` or equivalent runtime mapping).
- Overrides and trust state MUST remain principal-scoped.

6. Structured auditability
- Adapter MUST preserve decision context:
  - `tool`, `action`, `target`, `provenance_node_id`, `principal_id`
  - decision outcome and reason
  - policy/evaluation trace if available

## Required adapter API surface

An adapter is conformant if it provides a thin execution wrapper equivalent to:

```python
result = adapter.enforce_and_execute(
    tool="bash",
    action="exec",
    target="ls",
    provenance_node_id=node_id,
    parameters={"command": "ls /tmp"},
)
```

And internally enforces this flow:

1. `decision = policy.evaluate(...)` (optional, for preflight telemetry)
2. `execution_decision = policy.authorize_execution(..., execution_token=decision.execution_token)`
3. If outcome is `BLOCK` -> return deny (never execute sink)
4. Else execute sink with bounded args/target

## Non-conformant patterns (hard fail)

- Direct `subprocess`, SDK tool call, HTTP client, or filesystem write from model output path without MVAR authorization.
- Ignoring `authorize_execution` and only checking `evaluate`.
- Falling back to permissive behavior on token/policy errors.
- Global overrides shared across principals.

## Conformance verification

Run the pytest harness template in `conformance/pytest_adapter_harness.py` inside the adapter repo.

Pass criteria:
- Missing execution token -> BLOCK
- Token/provenance mismatch -> BLOCK
- Valid token + trusted bounded target -> ALLOW or STEP_UP
- Untrusted + critical sink path remains blocked by sink-policy mechanism (not capability-only short-circuit)
- Adapter does not execute sink when authorization fails

## Release policy recommendation

- First-party adapters MUST pass conformance harness in CI before release.
- Third-party adapters SHOULD publish harness results and MVAR version compatibility.
