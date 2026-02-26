# MVAR Architecture

This document describes the shipped architecture of MVAR Phase 1.

## System Boundary

MVAR is an in-process enforcement layer for agent runtimes. It does not replace OS sandboxing.

```mermaid
flowchart LR
    U[User / External Inputs] --> A[Agent Runtime]
    A --> P[Provenance Graph<br/>mvar-core/provenance.py]
    A --> C[Capability Runtime<br/>mvar-core/capability.py]
    A --> S[Sink Policy Engine<br/>mvar-core/sink_policy.py]
    P --> S
    C --> S
    S --> D{Outcome}
    D -->|ALLOW| X[Execute Sink]
    D -->|BLOCK| B[Reject Action]
    D -->|STEP_UP| H[Step-Up / Confirmation Path]
    S --> L[Decision Trace + Optional QSEAL]
```

## Enforcement Pipeline

Privileged actions are mediated at execution sinks through a deterministic decision path:

```mermaid
sequenceDiagram
    participant App as Agent/App
    participant Prov as Provenance
    participant Cap as Capability Runtime
    participant Pol as Sink Policy
    participant Sink as Privileged Sink

    App->>Prov: Create / propagate provenance labels
    App->>Pol: evaluate(tool, action, provenance_node_id, target)
    Pol->>Cap: Verify declared permission and target
    Pol->>Prov: Resolve integrity/confidentiality lineage
    Pol-->>App: Decision (ALLOW | BLOCK | STEP_UP) + trace
    alt ALLOW
      App->>Sink: Execute
    else BLOCK
      App-->>App: Abort execution
    else STEP_UP
      App-->>App: Require confirmation / policy step-up
    end
```

## Core Components

1. Provenance taint system: dual-lattice integrity/confidentiality labels with conservative propagation.
2. Capability runtime: deny-by-default permission model with per-target checks.
3. Sink policy engine: deterministic ALLOW/BLOCK/STEP_UP outcomes with traceable reasoning.
4. Adapter layer: framework-specific wrappers that route tool execution through sink-policy evaluation.

## Adapter Surfaces

First-party adapters exist for LangChain, OpenAI, MCP, Claude, AutoGen, CrewAI, and OpenClaw.

```mermaid
flowchart LR
    F[Framework Adapter<br/>mvar_adapters/] --> E[Shared Enforcement Path]
    E --> P[Provenance]
    E --> C[Capability]
    E --> S[Sink Policy]
    S --> O[Deterministic Outcome]
```

## Deterministic Invariant

The key Phase 1 invariant is:

`UNTRUSTED + CRITICAL -> BLOCK`

This gives structural enforcement at privileged sinks independent of payload semantics.

## Deployment Model (Phase 1)

- In-process library integration
- Explicit sink registration
- Optional QSEAL signing for tamper-evident decision artifacts
- Reproducible validation via `./scripts/launch-gate.sh`

## Validation Links

- Threat model and assumptions: [THREAT_MODEL.md](THREAT_MODEL.md)
- Adapter contract: [docs/ADAPTER_SPEC.md](docs/ADAPTER_SPEC.md)
- Conformance harness: [conformance/README.md](conformance/README.md)
- Research lineage: [DESIGN_LINEAGE.md](DESIGN_LINEAGE.md)
