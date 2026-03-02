# Unreleased

## Security and Runtime Hardening

- Added **security profile bootstrap API** in `mvar_core.profiles`:
  - `SecurityProfile.STRICT`
  - `SecurityProfile.BALANCED`
  - `SecurityProfile.MONITOR`
  - `create_default_runtime(...)` now provides secure-by-default initialization.

- Added **network exposure guardrails** for public-bind misconfiguration class:
  - deterministic detection of `0.0.0.0` / `::` bind variables
  - explicit allow + auth requirement for intentional public bind
  - covers March 2, 2026 incident class (~175,000 reported exposed instances)
  - wired into `mvar-doctor` and deployment demo startup checks

## Trust Proof and CI Artifacts

- Added **benign corpus regression suite** (`tests/test_benign_corpus.py`) for false-block monitoring.
- Added **security scorecard pipeline**:
  - `scripts/generate_security_scorecard.py`
  - `scripts/update_status_md.py`
  - `.github/workflows/security-scorecard.yml`
- Added break-attempt intake template:
  - `.github/ISSUE_TEMPLATE/break_mvar.md`

## Docs and Planning

- Added security profile reference: `docs/SECURITY_PROFILES.md`.
- Added two-week execution roadmap: `docs/TWO_WEEK_IMPLEMENTATION_PLAN.md`.
