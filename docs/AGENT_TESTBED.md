# Agent Testbed (Baseline vs MVAR)

Use this to test the same agent behavior with and without MVAR enforcement.

## What it does

- Runs a baseline agent (no sink enforcement)
- Runs an MVAR-protected agent (same planner, enforced execution boundary)
- Compares outcomes side-by-side

The shell tool is simulated only (no host side effects; safe demo).

## Run

```bash
python examples/agent_testbed.py --scenario injection
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
