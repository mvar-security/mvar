# MVAR Trust Map

This file maps public claims to reproducible commands and source artifacts.

## Reproducible Validation

Run from repo root:

```bash
pytest -q
./scripts/launch-gate.sh
python3 scripts/generate_security_scorecard.py
python3 scripts/update_status_md.py
```

Expected outcomes for `v1.2.0`:
- full suite: `261 passed`
- red-team gate: `7/7`
- adversarial corpus: `50/50 blocked`
- benign corpus: `200/200 passed`, `0 false blocks`

## Evidence Index

- Runtime profile defaults: `mvar-core/profiles.py`
- Exposure guardrails: `mvar-core/exposure_guardrails.py`
- Doctor check path: `demo/info.py`
- OpenClaw guardrail enforcement: `mvar_adapters/openclaw.py`
- OpenAI docker guardrail enforcement: `examples/deployment/openai_docker/app.py`
- Launch gate script: `scripts/launch-gate.sh`
- Release integrity check: `scripts/check_release_integrity.py`
- Security scorecard generation: `scripts/generate_security_scorecard.py`
- Status renderer: `scripts/update_status_md.py`

## CI Proof Surfaces

- Launch gate workflow: `.github/workflows/launch-gate.yml`
- Security scorecard workflow: `.github/workflows/security-scorecard.yml`
- Live status artifact: `STATUS.md`

## Incident-Class Coverage

For the March 2, 2026 public-bind exposure incident class (`0.0.0.0` / `::` misconfiguration), see:
- `docs/INCIDENT_CLASS_PUBLIC_BIND_MAR2_2026.md`

## Claims Discipline

MVAR claims are scoped to tested corpus + configured sink policy.
Do not generalize corpus results into universal security guarantees.
