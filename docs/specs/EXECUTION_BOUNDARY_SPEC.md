# MVAR Execution Boundary Specification
**Version:** 0.1
**Status:** Draft
**Reference Implementation:** MVAR runtime (github.com/mvar-security/mvar)

## Overview

This specification defines the minimum execution boundary contract
for AI agent runtimes. It is designed to be runtime-agnostic and
implementable by any agent framework.

## 1. Provenance Model

Every action submitted to a privileged execution sink MUST include:

| Field | Values | Description |
|---|---|---|
| source | model, user, system | Origin of the action request |
| trust_level | trusted, untrusted | Trust classification |
| trace_id | string | Unique trace identifier |

## 2. Critical Sink Categories

The following sink categories are defined as critical:

| Sink | Examples |
|---|---|
| shell | bash, exec, subprocess |
| filesystem | read, write, delete |
| network | HTTP, TCP, DNS |
| credentials | API keys, tokens, secrets |
| process_spawn | fork, spawn, daemon |

## 3. Enforcement Invariant

The core invariant of this specification:

UNTRUSTED input MUST NOT invoke CRITICAL sinks without explicit policy approval.

This invariant is deterministic. It does not depend on:
- Prompt classification
- Intent detection
- Model confidence scores
- Uncertainty quantification signals

## 4. Conformance

A runtime is considered conformant with this specification if:

1. All critical sink invocations are mediated by a policy decision
2. Provenance fields are propagated across agent boundaries
3. Policy decisions are logged with trace_id binding
4. Enforcement is fail-closed on missing or invalid provenance

## 5. Reference Implementation

MVAR implements this specification in full.

Verification:
pip install mvar-security
bash scripts/repro-validation-pack.sh

## 6. Versioning

This specification follows semantic versioning.
Breaking changes increment the major version.
Additive changes increment the minor version.

## Changelog
- v0.1 — Initial draft. Provenance model, sink categories, enforcement invariant.
