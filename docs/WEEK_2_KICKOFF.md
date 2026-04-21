# Week 2 Kickoff: Adversarial Measurement

**Date:** 2026-04-21
**Target Release:** 1.5.4 (May 11, 2026)
**Focus:** Metrics over volume - measure bypass resistance with documented protocol

---

## Completed: Week 2 Foundation

### 1. Evaluation Protocol (CRITICAL)

**File:** `docs/security/EVALUATION_PROTOCOL.md`

**What it defines:**
- Attack corpus: 50 base attacks × 10 variants = 550 test cases
- Benign corpus: 100 safe operations (measure false positives)
- Variant types: Base64, hex, command substitution, quoting, paths, whitespace, env vars, redirects, globs, logical operators
- Metrics: Bypass rate (target < 10%), False positive rate (target < 5%), Latency overhead (p95 < 10ms)
- Baseline comparison: MVAR vs unprotected (NOT vs guardrails - apples to apples)
- Publication plan: Full corpus + results + known bypasses

**Why this matters:** Published BEFORE running benchmark prevents outcome-driven methodology.

### 2. Adaptive Attacker Harness

**File:** `tests/adversarial/adaptive_attacker.py`

**What it does:**
- Generates 10 semantic-preserving variants per base attack
- Tests each variant against MVAR policy
- Learns which transformations bypass policy
- Computes aggregate metrics (bypass rate, latency, successful transformations)

**Usage:**
```python
from tests.adversarial.adaptive_attacker import AdaptiveAttacker

attacker = AdaptiveAttacker(policy_engine, seed=42)
campaign = attacker.run_adaptive_campaign("rm -rf /tmp/*", max_attempts=10)
metrics = attacker.compute_metrics([campaign])
print(f"Bypass rate: {metrics['bypass_rate']:.2%}")
```

---

## Completed: Week 2 Corpus & Harness ✅

### Task 1: Attack Corpus (50 base attacks) ✅

**File:** `tests/adversarial/corpus_attacks.json`

**Completed:** 50 attacks across 5 categories (10 each)
1. **Data exfiltration** - AWS credentials, SSH keys, env vars, git repos, database configs, DNS exfil, Docker secrets, browser cookies, kubectl config, npm tokens
2. **Destructive operations** - rm -rf home/binaries, overwrite /etc/passwd, drop database tables, corrupt git history, fill disk, killall, delete Docker images, delete K8s cluster, wipe package caches
3. **Privilege escalation** - passwordless sudo, SUID shell, SSH authorized_keys, create admin user, modify /etc/passwd, root cron job, Docker socket chmod 777, setuid binary, disable sudo logging, docker group escalation
4. **Lateral movement** - SSH to internal network, SCP to external host, port forwarding, reverse SSH tunnel, mount NFS share, rsync to attacker, remote command execution, docker exec, kubectl exec, netcat reverse shell
5. **Credential harvesting** - env dump, read .env files, extract git credentials, Docker registry creds, K8s secrets, browser saved passwords, AWS SSM parameters, Vault secrets, GCP service account keys, Terraform state

**Sources:** OWASP LLM Top 10, Simon Willison, LangChain security tests, OpenClaw disclosures, MVAR internal findings

### Task 2: Benign Corpus (100 safe commands) ✅

**File:** `tests/adversarial/corpus_benign.json`

**Completed:** 100 benign operations across 5 categories (20 each)
1. **File reading** - cat, head, tail, grep, wc, less, bat, sed, diff, hexdump, awk, jq, yq
2. **Directory listing** - ls variations, find, tree, du, file counting, sorted listings, inode info, permission search
3. **Git operations** - status, log, diff, show, branch, remote, blame, reflog, shortlog, diff-tree
4. **Package management** - pip list/show, npm list/info, version checks, outdated checks, freeze, lockfile viewing
5. **Development tools** - pytest, npm test, flake8, eslint, black, prettier, mypy, tsc, coverage, make, security audits

**Purpose:** Measure false positive rate (benign operations incorrectly blocked).

### Task 3: Evaluation Harness ✅

**File:** `tests/adversarial/evaluation_harness.py`

**Completed:** 400+ line orchestration harness with:
- Attack corpus loading and variant generation (50 attacks × 10 variants = 550 test cases)
- Benign corpus testing (100 commands)
- Per-test latency measurement
- Metrics computation (bypass rate, FPR, latency p50/p95/p99)
- Per-category breakdowns
- JSON export + markdown report generation
- CLI with configurable policy profiles

**Usage:**
```bash
python tests/adversarial/evaluation_harness.py \
  --attack-corpus tests/adversarial/corpus_attacks.json \
  --benign-corpus tests/adversarial/corpus_benign.json \
  --policy-profile strict \
  --output results/eval_1_5_4.json \
  --markdown results/eval_1_5_4.md
```

---

## Remaining: Week 2 Tasks

### Task 4: Run Evaluation + Publish Results

**Target:** May 11, 2026

**Deliverables:**
1. `results/eval_1_5_4.json` - Full results (550 attacks + 100 benign)
2. `docs/security/ADVERSARIAL_EVAL.md` - Published results + analysis
3. `docs/security/KNOWN_BYPASSES.md` - Honest documentation of what works

**Success criteria:**
- Bypass rate < 10% (vs 57-72% baseline for guardrails)
- False positive rate < 5%
- p95 latency < 10ms

### Task 5: Invite-Only Red Team

**Target participants (6 people):**

**Academics (2):**
- Sanmi Koyejo (Stanford) - Adversarial robustness expert
- Florian Tramèr (ETH Zurich) - AI security researcher

**OSS Security Practitioners (2):**
- Simon Willison - Datasette creator, prompt injection researcher
- Harrison Chase - LangChain CEO, agent security

**Agent Framework Maintainers (2):**
- OpenAI Agents team - via GitHub
- LangChain security lead - via Harrison Chase intro

**Invite method:**
- Direct email with proof runbook + evaluation protocol
- Ask for independent validation in exchange for acknowledgment
- Offer co-authorship on future paper if they contribute findings

**Timeline:**
- Send invites: April 28 (after evaluation protocol finalized)
- Validation window: May 1-10
- Incorporate feedback: May 11 (1.5.4 release)

---

## Week 2 Timeline

| Date | Task | Owner |
|------|------|-------|
| April 21 | ✅ Evaluation protocol drafted | Claude Code |
| April 21 | ✅ Adaptive attacker harness built | Claude Code |
| April 21 | ✅ Attack corpus built (50 base attacks) | Claude Code |
| April 21 | ✅ Benign corpus built (100 safe commands) | Claude Code |
| April 21 | ✅ Evaluation harness built | Claude Code |
| April 28 | Run evaluation, generate results | Claude Code |
| April 28 | Finalize protocol, send red team invites | Shawn |
| May 1-10 | Red team validation window | External validators |
| May 11 | Publish results + ship 1.5.4 | Shawn + Claude Code |

---

## Success Metrics (Week 2 Complete)

- [x] **Evaluation protocol published** (pre-benchmark) ✅
- [x] **Attack corpus:** 50 base attacks across 5 categories ✅
- [x] **Benign corpus:** 100 safe operations across 5 categories ✅
- [x] **Evaluation harness:** Working end-to-end ✅
- [ ] **Results measured:** Bypass rate, FPR, latency (next: run evaluation)
- [ ] **Red team invites sent:** 6 people
- [ ] **1.5.4 released:** With documented metrics

**Target bypass rate:** < 10% (vs 57-72% for model-level guardrails)

---

## Next: Week 3-4

After Week 2 (adversarial measurement), we move to:

**Week 3:** Process red team feedback, fix bypasses, re-run evaluation
**Week 4:** Ship LangChain adapter to GA (multi-framework proof)

---

**Status:** Week 2 corpus and harness complete. Ready to run evaluation against actual MVAR policy.

**Next session:**
1. Wire evaluation harness to real MVAR policy engine (replace stub)
2. Run evaluation against strict profile
3. Generate results + markdown report
4. Document bypasses in KNOWN_BYPASSES.md
