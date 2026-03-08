# Performance and Threat Model

## Performance Snapshot

| Metric | Value |
|---|---|
| Provenance node creation | ~5ms |
| QSEAL signing overhead | ~1ms (Ed25519) |
| Capability check | ~0.1ms |
| Sink policy evaluation | ~10ms (worst-case, full trace) |
| Typical enforcement overhead per privileged action | ~7ms (measured on Apple M1) |

Tradeoff: <10ms latency for deterministic execution-boundary enforcement.

Benchmark context: Apple M1, Python 3.11, local filesystem ledger, Ed25519 enabled.

## Non-Goals (Phase 1)

MVAR Phase 1 does not attempt to:

- Detect prompt injection using classifiers
- Classify malicious prompts using model heuristics
- Replace OS sandboxing (for example Docker/seccomp)
- Provide runtime model-weight verification

Phase 1 focus is deterministic execution invariants at privileged sinks.

## Threat Model and Assumptions

MVAR assumes:

- Untrusted external inputs (documents, web content, tool outputs)
- Honest-but-curious LLM behavior (may process malicious content)
- Existing OS/network hardening remains in place
- The deterministic policy layer itself is not compromised

Out of scope:

- Model weight poisoning
- Browser-layer vulnerabilities (for example CSWSH, XSS)
- Dependency supply-chain compromise
- Credential lifecycle management

Known limitations:

1. Graph write trust: if an attacker gains write access to provenance-state processes, trust labels can be forged. Mitigation is tamper-evident signing and verification.
2. Composition attacks: base sink policy evaluates actions independently; optional composition-risk controls (`MVAR_ENABLE_COMPOSITION_RISK=1`) add cumulative risk budgeting.
3. Manual sink annotation: sink registration is explicit and currently not automatic instrumentation.
