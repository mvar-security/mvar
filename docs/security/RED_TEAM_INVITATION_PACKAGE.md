# MVAR Red Team Invitation Package

Date: 2026-04-21
Status: Pre-1.5.4 validation package (no release/version bump in this branch)

## Why We Are Sending This

We are requesting independent validation of MVAR's adversarial resistance claims against our public corpus and adaptive variant harness.

We found and fixed a harness measurement issue, then reran controlled before/after testing to isolate policy impact.

## Harness Bug Disclosure

Issue discovered:
- `tests/adversarial/evaluation_harness.py` could import installed `mvar` (site-packages) instead of local repository code under test.

Fix:
- Force project-root path precedence in harness runtime import path.

Why it matters:
- Earlier measurements could conflate local code and installed code.
- Controlled reruns were required before using results for security claims.

## Controlled Methodology (A/B Isolation)

We held harness constant (fixed import behavior) and changed only policy implementation:

1. Baseline:
- Fixed harness
- Unpatched policy engine (`mvar/hooks/bash_policy.py`)

2. Post-patch:
- Same fixed harness
- Patched policy engine (encoding-aware + expanded high-risk rule set)

Both runs used:
- Attack corpus: `tests/adversarial/corpus_attacks.json` (50 attacks)
- Benign corpus: `tests/adversarial/corpus_benign.json` (100 commands)
- Variants per attack: `10`
- Profile: `strict`
- Seed: `42`

## Measured Results

Baseline (fixed harness, unpatched policy):
- Bypass rate: `86.20%`
- False positive rate: `0.00%`
- p95 latency: `0.04 ms`
- Artifact: `results/eval_baseline_fixed_harness.json`

Post-patch (fixed harness, patched policy):
- Bypass rate: `0.20%`
- False positive rate: `0.00%`
- p95 latency: `0.13 ms`
- Artifact: `results/eval_postpatch_fixed_harness.json`

## What Changed in Policy

Primary hardening areas:
- Encoding-aware inspection (base64/hex decode chains, `eval $(echo ...)` extraction)
- Normalization pass for common obfuscation tricks
- Expanded high-risk rules for exfiltration, lateral movement, privilege escalation, credential material access, and destructive operations
- Strict decision rule: any `critical` or `high` violation blocks

## What We Want Red Teamers to Validate

Please focus on:

1. Measurement integrity
- Confirm harness now evaluates local repository code.
- Confirm corpus + seed reproduce published metrics.

2. Evasion quality
- Attempt semantic-preserving bypasses not already represented.
- Prioritize polymorphic shell transformations and chained command substitutions.

3. False-positive pressure
- Stress benign but complex developer commands (tooling, package managers, CI workflows).
- Identify rule interactions that over-block legitimate workflows.

4. Residual edge case
- Review known residual case in `docs/security/KNOWN_BYPASSES.md`.

## Reproduction Commands

```bash
cd mvar

# Baseline
python tests/adversarial/evaluation_harness.py \
  --attack-corpus tests/adversarial/corpus_attacks.json \
  --benign-corpus tests/adversarial/corpus_benign.json \
  --policy-profile strict \
  --output results/eval_baseline_fixed_harness.json \
  --markdown results/eval_baseline_fixed_harness.md

# Post-patch
python tests/adversarial/evaluation_harness.py \
  --attack-corpus tests/adversarial/corpus_attacks.json \
  --benign-corpus tests/adversarial/corpus_benign.json \
  --policy-profile strict \
  --output results/eval_postpatch_fixed_harness.json \
  --markdown results/eval_postpatch_fixed_harness.md

# Multi-step staged scenarios
python -m pytest -q tests/test_adversarial_multistep_pack.py
```

## Regression Gate

A CI regression gate is now included:
- Fails if bypass rate exceeds `5%`
- Fails if false positive rate exceeds `5%`

File:
- `tests/test_adversarial_regression_gate.py`
- `tests/adversarial/corpus_multistep.json`
- `tests/test_adversarial_multistep_pack.py`
