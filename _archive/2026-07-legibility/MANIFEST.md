# _archive/2026-07-legibility — MVAR legibility reorg manifest

**Date:** 2026-07-07. **Rationale:** repository legibility. Nothing deleted — moved
only, via explicit `git mv` (history preserved). Per REORG_PLAN.md (bridge root).
Every candidate was grep-gated: only files with **zero external path-references** in
tracked docs/CI/scripts were moved.

## Moved (11 files)

### planning/ — the superseded planning trio (self-contained; only cross-reference each other)
| Source | Why archived |
|---|---|
| `PLANNING_IMPLEMENTATION_PHASES.md` | Pre-ship implementation-phases plan; now shipped. Only referenced within the trio. |
| `PLANNING_PROTECT_WRAPPER.md` | Planning for `protect()` (shipped). Only referenced within the trio. |
| `PLANNING_SPEC_SCHEMAS.md` | Planning for spec schemas (shipped under `spec/`). Only referenced within the trio. |

### sessions/ — dated one-off session/phase docs (no external references)
| Source | Why archived |
|---|---|
| `docs/SESSION_2026_04_21_GAP_CLOSURE_PLAN.md` | Dated session planning doc. |
| `docs/SESSION_2026_04_21_WEEK_2_BUILD.md` | Dated session build log. |
| `docs/WEEK_2_KICKOFF.md` | Superseded kickoff planning. |
| `docs/PHASE2_INTEGRATION_DEPLOYMENT_PLAN.md` | Phase-2 plan, superseded by shipped v1.5+. |

### results/ — clean dated eval dumps (isolated from the frozen dirty corpus files)
| Source | Why archived |
|---|---|
| `results/eval_baseline_fixed_harness.{json,md}` | Dated eval dumps; not read by any test/CI/script path. |
| `results/eval_postpatch_fixed_harness.{json,md}` | Dated eval dumps; not read by any test/CI/script path. |

## KEPT (grep-gate found external references — NOT moved)
- `docs/TWO_WEEK_IMPLEMENTATION_PLAN.md` — cited by `docs/releases/v1.2.0.md`.
- `docs/INCIDENT_CLASS_PUBLIC_BIND_MAR2_2026.md` — cited by `TRUST.md` (live governance doc) and `docs/releases/UNRELEASED.md`. Incident provenance linked from a trust doc = keep.

## DO-NOT-TOUCH (dirty tree — left exactly in place)
- `results/adversarial_eval_corpus_v2.{json,md}`, `results/adversarial_eval_corpus_v2.1_patched.{json,md}` — uncommitted adversarial-corpus work. The `results/` dir was NEVER moved wholesale; only the 4 clean files above were moved individually.
- `README.md`, `docs/security/KNOWN_BYPASSES.md`, `docs/security/CORPUS_V2_RESULTS.md`, `mvar/hooks/bash_policy.py`, `tests/adversarial/corpus_attacks.json`, and 5 untracked audit/outreach `.md`s — all dirty, untouched.
