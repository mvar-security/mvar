# MVAR Execution Contract Model (v1.4.0)

This page is the one-page architecture view for MVAR's execution-time enforcement model.

It shows the enforcement chain, not just components.

## Runtime Enforcement Chain

```text
              +-----------------------------------+
              | Signed Policy Bundle              |
              | Root of Trust                     |
              | (strict: Ed25519 verification)    |
              +----------------+------------------+
                               |
                               | policy load + verify
                               v
              +-----------------------------------+
              | MVAR Runtime Profile              |
              | permissive / balanced / strict    |
              | strict fails closed if            |
              | policy verification fails         |
              +----------------+------------------+
                               |
                               | policy evaluation
                               v
              +-----------------------------------+
              | Policy Decision Engine            |
              | allow / block / step_up           |
              +----------------+------------------+
                               |
                               | authorization issued
                               v
              +-----------------------------------+
              | Execution Contract (signed token) |
              |                                   |
              | binds:                            |
              | - policy bundle hash              |
              | - runtime profile                 |
              | - sink type                       |
              | - normalized invocation payload   |
              | - invocation hash                 |
              | - nonce + expiry                  |
              +----------------+------------------+
                               |
                               | sink verifies signed execution contract
                               | before execution
                               v
              +-----------------------------------+
              | Contract Verification             |
              | - signature verification          |
              | - invocation hash match           |
              | - nonce replay check             |
              | - policy bundle hash match       |
              +----------------+------------------+
                               |
                               | contract valid
                               v
              +-----------------------------------+
              | Sink Gateway                      |
              | enforced in v1.4.0:              |
              | - bash.exec                       |
              | - http.post                       |
              +----------------+------------------+
                               |
                               | execute only if contract verifies
                               v
              +-----------------------------------+
              | Privileged Action                 |
              +----------------+------------------+
                               |
                               | evidence emission
                               v
              +-----------------------------------+
              | Witness Ledger                    |
              | signed decision + chain metadata  |
              +-----------------------------------+
```

## Current Scope vs Next Scope

- Current enforced contract sinks (v1.4.0): `bash.exec`, `http.post`
- Next planned sinks: `filesystem.write`, credentialed tool invocation

## Three Security Guarantees

1. Policy Authenticity
- Strict mode requires signed policy verification at runtime startup.
- Strict mode fails closed when policy prerequisites are missing/invalid.

2. Deterministic Sink Enforcement
- Policy is enforced at execution sinks, not advisory middleware.
- Unauthorized execution is blocked before sink effects occur.

3. Verified Execution Contracts
- Privileged sink calls require contract evidence (in v1.4.0 scope above).
- Contracts bind policy state and invocation semantics to execution.
- Missing/invalid/mutated/replayed contract evidence is blocked.

## Threat Model Coverage (Current)

- Prompt injection -> sink policy enforcement
- Tool misuse -> sink contract verification
- Exfiltration -> strict default-deny HTTP egress unless allowlisted
- Decision/execution drift -> invocation hash contract binding
- Execution substitution -> sink/contract mismatch detection
- Replay -> nonce + expiry checks
- Policy tampering -> signed policy verification in strict mode

## Why This Is Different

Most frameworks:

```text
policy decision
   ->
log/trace
   ->
execute
```

MVAR:

```text
policy decision
   ->
execution contract issued
   ->
sink verifies contract
   ->
execute or block
   ->
signed witness recorded
```

## Attack Attempt vs MVAR Enforcement

```text
Agent proposes outbound exfiltration call
    |
    v
MVAR sink gateway intercepts http.post
    |
    v
No valid execution contract for this exact invocation
    |
    v
Execution blocked (fail-closed)
    |
    v
Signed denial witness emitted
```

## One-Sentence Explanation

MVAR requires verified execution contracts for privileged sink actions, binding policy decision and normalized invocation data to the exact operation before execution is allowed.
