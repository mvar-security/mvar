# Two-Week Implementation Plan (Undeniable v1.2)

This plan converts the "secure-by-default + public proof" initiative into a concrete 14-day track.

## Objectives

1. Remove trust drift between release tags, docs, and runtime behavior.
2. Make secure startup the default via profile bootstrap APIs.
3. Add deterministic guardrails for accidental public-bind deployments (Ollama/OpenClaw class).
4. Publish machine-readable security status artifacts from CI.

## Week 1 — Baseline Integrity + Guardrails

### Day 1-2: Release Integrity
- Cut `v1.1.1` from current `main` (do not rewrite `v1.1.0`).
- Ensure version fields, release notes, and tag SHA are consistent.
- Update `UNRELEASED.md` to reflect post-release delta only.

### Day 3-4: Secure Profiles
- Ship `mvar_core.profiles`:
  - `SecurityProfile.STRICT`
  - `SecurityProfile.BALANCED`
  - `SecurityProfile.MONITOR`
- Add contract tests preventing API drift in profile bootstrap paths.
- Update quickstart/README to use profile bootstrap.

### Day 5-7: Exposure Guardrails
- Add deterministic checks for public bind (`0.0.0.0`/`::`) with required explicit allow + auth.
- Document this as a direct mitigation for the March 2, 2026 incident class with widespread public reporting of exposed instances in this misconfiguration class.
- Enforce via `mvar-doctor` and deployment demo startup path.
- Add regression tests for:
  - blocked unsafe public bind
  - allowed public bind with explicit override + auth

## Week 2 — Public Proof Artifacts

### Day 8-10: Benign Corpus
- Add 200-vector benign corpus (`tests/test_benign_corpus.py`).
- Gate on "no benign BLOCK outcomes".
- Integrate into launch/scorecard CI paths.

### Day 11-12: Security Scorecard
- Generate `reports/security_scorecard.json` from reproducible checks.
- Render `STATUS.md` from scorecard.
- Publish as CI artifacts on push/PR.

### Day 13-14: Messaging + Launch Prep
- Add README links to scorecard artifacts and profile docs.
- Add break-attempt issue template + triage process.
- Final validation sweep:
  - `./scripts/launch-gate.sh`
  - `pytest -q`
  - scorecard workflow dry run

## Exit Criteria

- `main` and latest tag are release-consistent.
- Secure profile bootstrap is available and documented.
- Public-bind misconfiguration is blocked by default guardrails.
- Benign corpus and scorecard artifacts are CI-published and reproducible.
