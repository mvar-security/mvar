# MVAR Adversarial Evaluation Results

Date: 2026-04-22
Scope: `tests/adversarial/` corpus and adaptive variant harness
Policy engine: `mvar/hooks/bash_policy.py`

## Measurement Integrity Note

Prior runs mixed two changing variables:
1. policy engine hardening, and
2. harness import behavior.

The harness bug: `tests/adversarial/evaluation_harness.py` could import the installed `mvar` package from site-packages instead of the local repo under test. The harness now inserts project root into `sys.path` first, ensuring local source is evaluated.

To isolate policy contribution, we ran a controlled A/B sequence with the fixed harness:
1. Fixed harness + unpatched local policy (baseline)
2. Fixed harness + patched local policy (post-patch)

## Clean A/B Results (Fixed Harness in Both Runs)

- Baseline (unpatched local policy):
  - Raw bypass rate: `86.20%`
  - False positive rate: `0.00%`
  - p95 latency: `0.04 ms`
  - Artifact: `results/eval_baseline_fixed_harness.json`

- Post-patch (patched local policy):
  - Raw bypass rate: `0.20%`
  - Semantic-preserving bypass rate: `0.20%`
  - False positive rate: `0.00%`
  - p95 latency: `0.13 ms`
  - Artifact: `results/eval_postpatch_fixed_harness.json`

Result: policy hardening is the dominant driver of the improvement.

## Commands Used

```bash
cd mvar

# Baseline (fixed harness + unpatched policy)
python tests/adversarial/evaluation_harness.py \
  --attack-corpus tests/adversarial/corpus_attacks.json \
  --benign-corpus tests/adversarial/corpus_benign.json \
  --policy-profile strict \
  --seed 42 \
  --output results/eval_baseline_fixed_harness.json \
  --markdown results/eval_baseline_fixed_harness.md

# Post-patch (fixed harness + patched policy)
python tests/adversarial/evaluation_harness.py \
  --attack-corpus tests/adversarial/corpus_attacks.json \
  --benign-corpus tests/adversarial/corpus_benign.json \
  --policy-profile strict \
  --seed 42 \
  --output results/eval_postpatch_fixed_harness.json \
  --markdown results/eval_postpatch_fixed_harness.md
```

## Policy Hardening Implemented

1. Added decode/normalization pipeline for obfuscation patterns:
- Base64 decode chains
- Hex decode chains
- `eval $(echo ...)` extraction
- Command normalization for whitespace and common env indirections

2. Expanded high-risk detection coverage:
- Exfiltration primitives (`curl`, `scp`, `rsync`, DNS payload-like queries)
- Lateral movement primitives (`ssh`, reverse shell patterns)
- Privilege escalation primitives (`sudoers`, `chmod u+s`, account mutation)
- Credential material access (`.aws`, `.kube`, `.docker`, `gcloud`, browser stores, `terraform.tfstate`)
- Destructive operations (`rm -rf` critical paths, `dd` to block devices, cluster-wide deletes)

3. Hardened decision policy:
- Any `critical` or `high` severity violation returns `block`

## Artifacts

- Baseline JSON: `results/eval_baseline_fixed_harness.json`
- Baseline markdown: `results/eval_baseline_fixed_harness.md`
- Post-patch JSON: `results/eval_postpatch_fixed_harness.json`
- Post-patch markdown: `results/eval_postpatch_fixed_harness.md`
