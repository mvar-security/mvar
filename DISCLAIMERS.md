# DISCLAIMERS

## Security Scope

MVAR enforces deterministic policy decisions at registered execution sinks under stated assumptions.

The guarantees described in this repository depend on:

- Complete mediation through MVAR at execution boundaries
- Correct sink registration and adapter routing
- Correct provenance labeling and policy configuration
- Integrity of the host/runtime environment

## Not a Completeness Proof

Validation results in this repository (including attack-corpus results) characterize behavior under tested conditions and configurations.  
They are not a proof of security against all possible attacks.

## Defense-in-Depth Requirement

MVAR is intended to be one layer in a broader security architecture.  
It does not replace:

- OS/container sandboxing
- network segmentation and egress controls
- credential lifecycle management
- supply-chain controls
- secure SDLC and incident response practices

## No Warranty

This software is provided under Apache 2.0 on an "AS IS" basis, without warranties or conditions of any kind.

## Compliance and Legal Use

Users are responsible for evaluating legal, regulatory, and compliance requirements for their deployment context.

