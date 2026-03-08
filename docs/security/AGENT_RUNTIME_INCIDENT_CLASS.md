# Why Agent Runtimes Need Execution Boundaries

## Problem Class

As soon as an AI agent can execute actions (shell, APIs, files, credentials), prompt injection shifts from a content problem to an execution-authority problem.

The failure mode is consistent:

1. Untrusted content influences model output.
2. Model output is translated into tool calls.
3. Privileged action executes without a deterministic boundary check.

At that point, runtime impact is possible even when prompt filters are present.

## Why Prompt Filtering Alone Fails

Prompt filtering is useful but non-deterministic:

- coverage is incomplete against novel or obfuscated payloads
- behavior can drift with model, prompt, or tool-chain changes
- it does not guarantee sink-level enforcement

When execution authority exists, the control point must be the execution sink.

## Boundary Model

Execution-boundary security treats policy as a precondition to action:

- classify provenance/integrity of input-derived data
- classify sink risk (low/medium/high/critical)
- enforce deterministic runtime policy before privileged execution

Core invariant:

`UNTRUSTED input + CRITICAL sink -> BLOCK`

## What This Means in Practice

For agent-runtime operators, this shifts security posture from:

- "we tried to detect bad prompts"

to:

- "unsafe execution paths cannot run under policy"

This is the distinction between advisory controls and runtime enforcement controls.

## MVAR Positioning

MVAR is a deterministic execution-boundary layer:

- integrated at tool-execution paths
- testable through benign-allow / adversarial-block proofs
- designed for adapter-based integration across modern agent runtimes

See:

- governed MCP proof: [../outreach/GOVERNED_MCP_RUNTIME_PROOF.md](../outreach/GOVERNED_MCP_RUNTIME_PROOF.md)
- attack validation showcase: [../ATTACK_VALIDATION_SHOWCASE.md](../ATTACK_VALIDATION_SHOWCASE.md)
