# Unreleased

## Post-v1.3.0

- Release `v1.3.0` cut with strict-mode enterprise hardening.
- See [v1.3.0 release notes](./v1.3.0.md) for shipped changes.

## Maintainer and Adoption Hygiene

- Added integration-request intake template:
  - `.github/ISSUE_TEMPLATE/integration_request.md`
  - captures target framework, boundary scope, and acceptance criteria for first-party adapters

- Added integration playbook contact link:
  - `.github/ISSUE_TEMPLATE/config.yml`
  - routes requesters to `docs/AGENT_INTEGRATION_PLAYBOOK.md` before filing

- Refreshed repository security status metadata:
  - `STATUS.md` regenerated from scorecard artifact
  - package/runtime version strings aligned to `1.2.2`

## Adoption and Trust Surfaces

- Added top-level trust map: `TRUST.md`
  - maps public claims to reproducible commands and source artifacts
  - links CI proof surfaces (`launch-gate`, scorecard, status artifact)

- Added incident-class explainer:
  - `docs/INCIDENT_CLASS_PUBLIC_BIND_MAR2_2026.md`
  - documents public-bind misconfiguration pattern and MVAR guardrail behavior

- Added pinned discussion draft for adoption blockers:
  - `docs/issues/PINNED_CLONER_FEEDBACK_DISCUSSION.md`
  - structured prompt for converting cloners into actionable feedback

- Updated README conversion path:
  - added “Verify in 60 Seconds”
  - added “Why v1.2.0 Matters”
  - added “Trust & Verification” index

## Operator Reliability

- Added environment preflight script: `scripts/doctor-environment.sh`
  - warns on wrong working directory
  - warns on wrong/absent venv
  - prints canonical validation path

- Added one-command verification script: `scripts/quick-verify.sh`
  - bootstraps local `.venv` if missing
  - installs package with build-isolation fallback
  - runs pytest, launch-gate, scorecard generation, status render

- Added troubleshooting playbook: `docs/TROUBLESHOOTING.md`
  - maps common copy/paste failures to deterministic fixes
  - includes canonical validation commands + expected outcomes

- Hardened repro installer: `scripts/clean_venv_repro.sh`
  - packaging tool upgrade now warning-tolerant in restricted networks
  - retries install without build isolation
  - falls back to `--system-site-packages` when setuptools is missing in isolated venvs

- Hardened ledger runner: `scripts/run_ledger_tests.sh`
  - uses pytest execution path (instead of raw file execution)
  - supports active-venv and shell pytest discovery fallback
