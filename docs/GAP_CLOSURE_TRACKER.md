# Gap Closure Tracker - Path to Category Leadership

**Goal:** Move from "impressive build" to "credible category leader" by closing product-trust gaps.

**Timeline:** 6 weeks (April 21 - June 1, 2026)

**Success Metric:** Independent security researchers + enterprises can validate MVAR's claims in < 1 hour.

---

## Week 1: Scope Truth (April 21-27)

**Objective:** Honest communication about what's production-ready vs planned.

### Tasks

- [x] **Create support matrix** - `docs/SUPPORT_MATRIX.md`
  - Status: ✅ Complete
  - Claude Code marked as GA, others as Planned/Experimental
  - Clear GA criteria defined

- [x] **Document QSEAL signature modes** - `docs/security/QSEAL_MODES.md`
  - Status: ✅ Complete
  - HMAC vs Ed25519 tradeoffs documented
  - Corrects "non-repudiation" overclaim for HMAC mode

- [x] **Create prior art comparison** - `docs/security/PRIOR_ART.md`
  - Status: ✅ Complete
  - Precise positioning vs academic work, OSS, commercial
  - "First" claim scoped with evidence table

- [ ] **Update README with scope reality**
  - Add "Production Ready: Claude Code" section at top
  - Link to SUPPORT_MATRIX.md for other frameworks
  - Replace vague multi-framework claims with roadmap

- [ ] **Disable/warn on unsupported framework paths in CLI**
  ```python
  # mvar/cli.py
  if args.framework != "claude-code":
      print(f"⚠️  {args.framework} is not production-ready yet.")
      print(f"   See docs/SUPPORT_MATRIX.md for status.")
      print(f"   Continue anyway? (y/N)")
  ```

- [ ] **Create 10-minute proof runbook** - `docs/PROOF_RUNBOOK.md`
  - Status: ✅ Complete (draft)
  - Needs testing by external user (recruit from Anthropic Discord)

**Deliverable:** Brutally honest documentation. No one can accuse us of overpromising.

---

## Week 2: Policy Depth (April 28 - May 4)

**Objective:** Expand from demo-quality bash rules to production-grade policy library.

### Tasks

- [ ] **Create threat taxonomy** - `docs/security/THREAT_TAXONOMY.md`
  - Map MITRE ATT&CK techniques to required MVAR rules
  - Example: T1552.001 (Unsecured Credentials) → rule pattern `(aws|\.ssh|credentials)` in exfiltration attempts
  - Target: 50 ATT&CK techniques mapped

- [ ] **Expand bash policy from 23 → 100 rules**
  - Current: `mvar/hooks/bash_policy.py` has ~23 patterns
  - Categories to add:
    - Data exfiltration (curl/wget to unknown domains, clipboard access)
    - Privilege escalation (sudo, su, chmod +s)
    - Lateral movement (ssh, scp to non-allowlisted hosts)
    - Persistence (cron, systemd service creation)
    - Credential harvesting (env var dumps, .ssh key access)

- [ ] **Create policy test corpus**
  - `tests/policies/corpus_benign.json` - 100 safe commands
  - `tests/policies/corpus_malicious.json` - 100 attack commands
  - `tests/policies/corpus_evasive.json` - 50 bypass attempts
  - Test: All benign pass, all malicious block, <5% evasive succeed

- [ ] **Add policy rule scoring**
  ```python
  # mvar_core/policy_scoring.py
  class RuleScore:
      true_positives: int   # Real attacks caught
      false_positives: int  # Benign commands blocked
      bypasses: int         # Evasions that succeeded

      @property
      def efficacy(self) -> float:
          return true_positives / (true_positives + bypasses)
  ```

- [ ] **Policy version enforcement**
  - Add `policy_version` field to all decisions
  - Reject decisions signed with outdated policy (for strict mode)
  - Support policy rollback for incident investigation

**Deliverable:** 100+ production-grade rules with test coverage. Policy efficacy metrics published in README.

---

## Week 3: Adversarial Proof (May 5-11)

**Objective:** Prove bypass resistance with empirical red team results.

### Tasks

- [ ] **Build adaptive attacker harness**
  ```python
  # tests/adversarial/adaptive_attacker.py
  class AdaptiveAttacker:
      """Learns from blocked attempts and generates variants."""
      def attempt_exfiltration(self, max_attempts=10):
          # Generate attack, learn from block, adapt
  ```

- [ ] **Run Stanford Koyejo-style bypass benchmark**
  - Take 50 attacks from `corpus_malicious.json`
  - For each blocked attack, generate 10 semantic variants
  - Measure bypass rate (target: <10% vs 57-72% baseline for guardrails)
  - Document: `docs/security/ADVERSARIAL_EVAL.md`

- [ ] **Recruit external red team**
  - Post bounty on Twitter/LinkedIn: "$500 for reproducible MVAR bypass"
  - Rules: Must be tool-call injection (not model jailbreak), reproducible, novel
  - Every bypass becomes regression test + new rule

- [ ] **Publish failure cases**
  - `docs/security/KNOWN_BYPASSES.md` - Be honest about what works
  - For each bypass: Attack vector, root cause, fix status, regression test link

- [ ] **Create bypass regression test suite**
  ```python
  # tests/adversarial/test_known_bypasses.py
  def test_bypass_001_base64_obfuscation():
      """CVE-2026-MVAR-001: Base64-encoded rm command"""
      attack = "echo 'cm0gLXJmIC8=' | base64 -d | bash"
      result = policy_engine.evaluate(attack)
      assert result.decision == "block", "Bypass regression"
  ```

**Deliverable:** Published bypass rate < 10% with public red team results. Honest about limitations.

---

## Week 4: Framework Reality (May 12-18)

**Objective:** Ship two fully-working framework adapters beyond Claude Code.

### Focus: LangChain + OpenAI (highest adoption)

- [ ] **LangChain adapter - full implementation**
  - Hook: `BaseTool.run()` interception
  - Installer: `mvar init --framework langchain`
  - Verification: `mvar verify --framework langchain`
  - Tests: 10+ integration tests (tool call → policy → QSEAL)
  - Docs: `docs/frameworks/LANGCHAIN.md`

- [ ] **OpenAI Agents SDK adapter - full implementation**
  - Hook: Function calling interception
  - Installer: `mvar init --framework openai-agents`
  - Tests: 10+ integration tests
  - Docs: `docs/frameworks/OPENAI_AGENTS.md`

- [ ] **Adapter conformance test suite**
  - Every adapter must pass same 20-test suite
  - Tests: Policy enforcement, QSEAL signing, MC reporting, error handling
  - Prevents adapter drift

- [ ] **Update support matrix**
  - Move LangChain + OpenAI from "Planned" → "GA"
  - Update README: "Production ready for Claude Code, LangChain, OpenAI Agents"

**Deliverable:** 3 frameworks in GA (Claude Code, LangChain, OpenAI). Multi-framework claim is now credible.

---

## Week 5: Enterprise Operability (May 19-25)

**Objective:** Enable team deployments with centralized policy + key management.

### Tasks

- [ ] **HashiCorp Vault integration**
  ```python
  # mvar_core/secrets/vault_backend.py
  class VaultSecretBackend:
      def get_qseal_secret(self) -> bytes:
          # Read from Vault instead of ~/.mvar/.mvar.env
  ```
  - Enables centralized key rotation
  - Docs: `docs/enterprise/VAULT_INTEGRATION.md`

- [ ] **Policy bundle versioning**
  - Policy bundles get semver (v1.0.0, v1.1.0)
  - Team admin pushes canonical policy to S3/GCS
  - Developer hooks fetch + verify signed policy on startup
  - Prevents policy drift across team

- [ ] **Mission Control team dashboard**
  - Aggregate decisions from all team members
  - Team lead sees: Who triggered violations, when, what command
  - Incident response workflow: Block → Alert → Investigate → Allowlist/Fix

- [ ] **RBAC for policy management**
  - Roles: Developer (read-only), Lead (allowlist), Admin (edit policy)
  - Audit log: Who changed what policy rule, when, why

- [ ] **Compliance reporting**
  - Generate SOC2-style report: "All agent actions audited with crypto provenance"
  - Export signed decision ledger for external audit
  - Docs: `docs/enterprise/COMPLIANCE_REPORTING.md`

**Deliverable:** "Team mode" that works for 5-50 developers. Enterprise POC-ready.

---

## Week 6: Proof Packaging (May 26 - June 1)

**Objective:** Make validation effortless for researchers + enterprises.

### Tasks

- [ ] **10-minute proof runbook (finalize + test)**
  - Status: Draft exists
  - Recruit 5 external users to run it cold (no prior MVAR knowledge)
  - Fix any friction points
  - Target: 95% succeed in < 10 minutes

- [ ] **Comparison artifact: MVAR vs baseline runtime**
  ```bash
  # benchmark/compare_baseline.sh
  # Run same agent workflow with/without MVAR
  # Measure: Latency overhead, block rate, false positives
  ```
  - Publish results: `docs/BENCHMARKS.md`

- [ ] **Auditor-focused documentation**
  - `docs/audit/VERIFICATION_GUIDE.md` - How to verify QSEAL signatures
  - `docs/audit/SCHEMA_REFERENCE.md` - Decision schema specification
  - `docs/audit/GUARANTEES_AND_LIMITS.md` - What MVAR promises (and doesn't)

- [ ] **Academic paper submission (optional)**
  - ArXiv preprint: "Information Flow Control for LLM Agents: Design and Evaluation"
  - Co-authors: Shawn Cohen + external reviewers who contributed red team findings
  - Benchmark: MVAR vs NeMo Guardrails vs unprotected agent

- [ ] **GitHub Release Package**
  - Tag: v1.6.0
  - Release notes: All gap closure work completed
  - Artifacts: Signed wheel, source tarball, benchmark results, adversarial eval
  - Announcement: "MVAR 1.6.0 - Production Ready for Enterprise Teams"

**Deliverable:** Zero-friction validation path. Researchers can reproduce all claims in 1 hour.

---

## Success Metrics (Week 6 Completion)

### Quantitative

- [ ] **Bypass rate < 10%** (vs 57-72% guardrail baseline)
- [ ] **3 frameworks GA** (Claude Code, LangChain, OpenAI)
- [ ] **100+ policy rules** with test coverage
- [ ] **10-minute proof runbook** - 95% success rate with cold users
- [ ] **External validation** - 3+ independent security researchers confirm claims

### Qualitative

- [ ] **Honest positioning** - No overclaims, all "firsts" have evidence
- [ ] **Trust signals** - Third-party audit, public red team, published bypasses
- [ ] **Enterprise ready** - Team mode works for 5-50 developers
- [ ] **Validation effortless** - Researchers can verify in < 1 hour

---

## Weekly Standup Template

**Week N:** [Date Range]

**Completed:**
- [ ] Task 1
- [ ] Task 2

**In Progress:**
- [ ] Task 3 (ETA: ...)

**Blocked:**
- None / Issue: ...

**Next Week Focus:**
- ...

---

## After Week 6: What Changes?

**Before (1.5.2):**
- "MVAR is a promising prototype with interesting ideas"
- "Need to see production deployment before we can evaluate"
- "Unclear if this works beyond Claude Code"

**After (1.6.0):**
- "MVAR has empirical bypass rate of 8% (vs 57-72% baseline)"
- "Three frameworks in production, team deployments working"
- "Independent red team + academic validation confirm claims"
- "We can reproduce all results in 1 hour"

**The shift:** From "interesting prototype" to "credible category leader with validated claims."

---

**Owner:** Shawn Cohen
**Reviewers:** Claude Code (implementation), Codex (validation), Claude.ai (positioning)
**Last Updated:** 2026-04-21
