# MVAR Attack Validation Showcase

This page summarizes reproducible baseline-vs-MVAR outcomes from the local agent
testbed (`examples/agent_testbed.py`).

Security model focus:
- deterministic sink enforcement at execution boundaries
- conservative provenance propagation (untrusted data stays untrusted)
- signed decision traces (`qseal_algo`, `qseal_sig`) for auditability

Core invariant:

`UNTRUSTED + CRITICAL -> BLOCK`

## Scenarios

| Scenario | Attack / Pattern | Baseline (no enforcement) | MVAR outcome | Why |
|---|---|---|---|---|
| `rag_injection` | Untrusted retrieved content injects shell command | ALLOW + simulated execution | BLOCK + no execution | Untrusted provenance reaches critical shell sink |
| `taint_laundering` | Encoded payload decoded by planner then executed | ALLOW + simulated execution | BLOCK + no execution | Decoding does not remove taint; critical sink still blocked |
| `benign` | Safe read path (`filesystem.read`) | ALLOW + simulated execution | ALLOW + simulated execution | Low-risk sink with acceptable policy path |

Notes:
- The shell and filesystem operations are simulated only (no host side effects).
- QSEAL signature values vary per run; compare outcome logic and trace fields.

## Reproduce Locally

```bash
git clone https://github.com/mvar-security/mvar.git
cd mvar
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip setuptools wheel
python -m pip install .

python examples/agent_testbed.py --scenario rag_injection
python examples/agent_testbed.py --scenario taint_laundering
python examples/agent_testbed.py --scenario benign
```

What to confirm in output:
- baseline executes attack scenarios
- MVAR blocks attack scenarios before sink execution
- benign scenario remains allowed
- trace includes: `policy_hash`, `sink_classified`, integrity/confidentiality labels, invariant line, and QSEAL fields

## Scope

This showcase demonstrates deterministic enforcement behavior for these
scenarios under current sink registration and labeling assumptions.

It is not a proof of completeness against all possible attacks.
See [THREAT_MODEL.md](../THREAT_MODEL.md) for assumptions and limits.

## Extend the Corpus

If you have adversarial variants that should be tested, submit them via:
[ATTACK_VECTOR_SUBMISSIONS.md](./ATTACK_VECTOR_SUBMISSIONS.md).
