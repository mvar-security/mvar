# Security Policy

## Supported Version

Security fixes are provided for the latest `main` branch.

## Reporting a Vulnerability

Please report vulnerabilities privately before public disclosure.

- Contact: `security@mvar.io`
- Subject: `MVAR Security Report`
- Include:
  - Reproduction steps
  - Affected commit/version
  - Impact assessment
  - Any proof-of-concept code or logs

## Disclosure Expectations

- We will acknowledge receipt as soon as possible.
- We will triage, reproduce, and provide a mitigation plan.
- Please avoid public disclosure until a fix or mitigation is available.

## Scope Notes

- MVAR enforces deterministic controls at registered execution sinks.
- Security guarantees depend on adapter conformance and correct sink routing.
- Use the adapter contract and conformance harness:
  - `docs/ADAPTER_SPEC.md`
  - `conformance/pytest_adapter_harness.py`
