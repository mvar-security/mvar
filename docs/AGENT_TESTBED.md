# Agent Testbed (Baseline vs MVAR)

Use this to test the same agent behavior with and without MVAR enforcement.

## What it does

- Runs a baseline agent (no sink enforcement)
- Runs an MVAR-protected agent (same planner, enforced execution boundary)
- Compares outcomes side-by-side

The shell tool is simulated only (no host side effects; safe demo).

## Run

```bash
python examples/agent_testbed.py --scenario rag_injection
```

Expected outcome:
- Baseline: `executed: True`
- MVAR: `outcome: BLOCK` and `executed: False`
- MVAR trace includes deterministic invariant line: `UNTRUSTED + CRITICAL -> BLOCK`
- MVAR trace includes QSEAL details (`qseal_algo`, `qseal_sig`)

## Optional benign scenario

```bash
python examples/agent_testbed.py --scenario benign
```

This helps verify normal-path behavior in the same harness.

## Optional taint-laundering scenario

```bash
python examples/agent_testbed.py --scenario taint_laundering
```

This verifies that decoded/rewritten malicious content from untrusted retrieval
still blocks at critical sinks.

## Scenario matrix

| Scenario | Baseline | MVAR |
|----------|----------|------|
| `rag_injection` | ALLOW + simulated execution | BLOCK + no execution |
| `taint_laundering` | ALLOW + simulated execution | BLOCK + no execution |
| `benign` | ALLOW + simulated execution | ALLOW + simulated execution |

## Community challenge

If you have additional adversarial prompts or retrieval payloads, submit them via:
[docs/ATTACK_VECTOR_SUBMISSIONS.md](ATTACK_VECTOR_SUBMISSIONS.md)
