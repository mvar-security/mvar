# Incident Class: Public Bind Misconfiguration (March 2, 2026)

## Summary

A widely discussed incident class on March 2, 2026 involved local-model services exposed to the internet due to binding to non-loopback addresses (`0.0.0.0` / `::`) without authentication. Public reporting cited roughly 175,000 exposed instances.

MVAR addresses this class with deterministic runtime guardrails.

## Threat Pattern

Common misconfiguration sequence:
1. local model/gateway binds to `0.0.0.0` or `::`
2. no auth token/API key requirement is set
3. service becomes reachable from untrusted networks

Risk outcomes:
- remote invocation of local model endpoints
- data exfiltration via tools or prompt-injection chains
- unauthorized workload execution

## MVAR Guardrail Behavior

MVAR checks environment posture and fails closed when this class is detected.

Detected bind env keys:
- `OLLAMA_HOST`
- `OPENCLAW_HOST`
- `OPENCLAW_BIND_HOST`
- `MVAR_BIND_HOST`
- `HOST`

Blocked unless both conditions are true:
- explicit allow flag (`MVAR_ALLOW_PUBLIC_BIND=1` or equivalent)
- authentication is configured (`MVAR_GATEWAY_AUTH_TOKEN`, `OPENCLAW_API_KEY`, `OLLAMA_API_KEY`, or `MVAR_AUTH_REQUIRED=1`)

## Verification

```bash
mvar-doctor
```

Expected on unsafe posture:
- doctor reports `status: BLOCK`
- clear issue list for bind/auth mismatch

Expected on explicit + authenticated posture:
- doctor reports `status: OK`
- warning reminds to enforce network controls/TLS

## Operational Guidance

- Prefer loopback-only bind for local development.
- Require auth when bind is non-loopback.
- Keep external firewall rules and TLS enabled.
- Treat public-bind mode as deliberate, auditable configuration.

## Relevant Source Files

- `mvar-core/exposure_guardrails.py`
- `demo/info.py`
- `examples/deployment/openai_docker/app.py`
- `mvar_adapters/openclaw.py`
