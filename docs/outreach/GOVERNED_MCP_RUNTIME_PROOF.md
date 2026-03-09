# Governed AI Runtime: Reproducible MCP Enforcement Proof

This page demonstrates benign-allow / adversarial-block behavior for MCP-style tool execution under governed runtime enforcement. If you are evaluating agent-runtime risk classes discussed around OpenClaw-style incidents, this is the reproducible runtime boundary proof: privileged tool actions are gated by execution-envelope validation, and invalid paths are blocked before execution.

This is runtime enforcement, not prompt filtering. The control point is the privileged execution sink.

The included demo shows:

- benign MCP request: allowed and executed
- adversarial prompt-injection request: deterministically blocked
- evidence chain: emitted for both outcomes

This proof focuses on runtime enforcement behavior rather than policy suggestions or prompt filtering.

---

## What This Demonstrates

The governed runtime enforces several invariants:

1. Execution authorization: privileged actions require a validated execution envelope.
2. Replay protection: envelopes include nonce and expiry checks.
3. Lineage tracking: handoffs include parent trace identifiers.
4. Evidence emission: each decision emits verifiable metadata.

These checks occur before tool execution, so prompt manipulation cannot bypass the execution boundary.

---

## Reproduce in One Command

From repo root:

```bash
python demo/governed_mcp_toolchain_demo.py
```

Expected assertion fields in output:

- `assertions.benign_allowed = true`
- `assertions.adversarial_blocked = true`
- `assertions.adversarial_tool_not_executed = true`
- `assertions.evidence_present_all = true`

---

## Validation Test

```bash
pytest -q tests/e2e/test_governed_mcp_toolchain_demo.py
```

This test validates:

- benign path executes and returns success
- adversarial path is blocked
- blocked path has `execution.executed = false`
- evidence fields exist (`envelope_core_hash`, `envelope_full_hash`, signature algorithm)
- trace linkage is present for chained governed calls

Witness verification (portable artifact check):

```bash
mvar-verify-witness data/mvar_decisions.jsonl --require-chain
```

---

## Runtime Path (Simplified)

```text
MCP Tool Request
    |
    v
Execution Governor
    |
    v
Verification + Policy
    |
    +--> BLOCK --> Evidence emitted
    |
    +--> ALLOW --> Tool executes --> Evidence emitted
```

---

## Current Scope

Shipped now:

- governed MCP demo script
- E2E test coverage for benign/adversarial behavior
- CI gate execution + proof artifact emission

Pending manual lock:

- mark `Governed Runtime Contract Gate (Python 3.12)` as required in branch protection on `main`
