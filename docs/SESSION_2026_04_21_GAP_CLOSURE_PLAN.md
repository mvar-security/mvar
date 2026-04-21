# Session 2026-04-21: Gap Closure Plan

**Context:** Post-1.5.2 release, received detailed assessments from Claude.ai and Codex identifying gaps between "impressive build" and "category leader."

**Outcome:** 6-week plan to close product-trust gaps with concrete deliverables.

---

## What We Built Today

### 1. Honest Positioning Documents

**Created:**
- `docs/SUPPORT_MATRIX.md` - Honest framework support status (only Claude Code is GA)
- `docs/security/QSEAL_MODES.md` - Corrects HMAC non-repudiation overclaim, documents Ed25519 roadmap
- `docs/security/PRIOR_ART.md` - Precise positioning vs academic/OSS/commercial with evidence table
- `docs/PROOF_RUNBOOK.md` - 10-minute reproducible proof (install → attack → block → signed artifact)
- `docs/GAP_CLOSURE_TRACKER.md` - 6-week execution plan with weekly milestones

**Key Corrections:**
1. **HMAC ≠ Non-Repudiation:** HMAC provides tamper-evidence within trust boundary, not third-party verifiable non-repudiation. Ed25519 mode planned for true non-repudiation.

2. **"First" Claims Need Evidence:** Created prior art comparison table proving: "First open-source, installable IFC enforcement runtime for LLM agents with cryptographic decision audit at the tool-call boundary." Each word is load-bearing and excludes specific alternatives.

3. **Multi-Framework Reality:** Only Claude Code is GA. Others are stubs or planned. Now documented honestly in support matrix.

---

## The Assessments (Summary)

### Claude.ai's Gap Analysis

**What MVAR Is:**
> "Working information flow control enforcement at the tool-call boundary of LLM agents with cryptographic audit provenance."

**Positioning:**
> "The right response to an unpreventable class of attacks (prompt injection) is auditable constraint, not prevention."

**Gaps Identified:**
1. Policy engine not comprehensive (23 rules insufficient vs adaptive adversaries)
2. No adversarial red-team validation (no Stanford Koyejo-style bypass testing)
3. Multi-framework support incomplete (stubs only for most frameworks)
4. Enterprise deployment unproven (single developer only, no team key management)
5. Threat model not validated against real attackers

### Codex's Corrections + Plan

**Critical Corrections:**
1. **HMAC limitation:** "HMAC gives integrity/authenticity for parties sharing the secret, but not full third-party non-repudiation."
2. **"First" claims:** "Should be softened unless you maintain a strict prior-art table."

**Gap-Closure Prescription:**
1. Scope truth (immediate) - Support matrix, disable unsupported paths
2. Policy depth (2-4 weeks) - Expand to 100+ rules, corpus testing, metrics
3. Adversarial proof (2-4 weeks) - Red team, bypass rate < 10%
4. Framework reality (4-6 weeks) - Ship LangChain + OpenAI fully
5. Enterprise operability (parallel) - Vault, policy versioning, RBAC
6. Proof packaging (1-2 weeks) - 10-min runbook, comparison artifact, auditor docs

**Bottom Line:**
> "You are not missing 'just exposure.' You are missing a small set of product-trust and proof-scaling steps. Do those, and exposure will convert into adoption instead of just attention."

---

## 6-Week Execution Plan

### Week 1: Scope Truth (April 21-27) ✅ Partially Complete

**Completed Today:**
- [x] Support matrix created
- [x] QSEAL modes documented (HMAC vs Ed25519)
- [x] Prior art comparison with evidence table
- [x] 10-minute proof runbook drafted

**Remaining:**
- [ ] Update README with scope reality section
- [ ] Disable/warn on unsupported framework CLI paths
- [ ] Test proof runbook with external users

### Week 2: Policy Depth (April 28 - May 4)

**Goal:** Expand from 23 demo rules to 100+ production-grade rules.

**Key Tasks:**
- Create MITRE ATT&CK threat taxonomy (50 techniques mapped)
- Expand bash policy: 23 → 100 rules
- Build test corpus: 100 benign, 100 malicious, 50 evasive
- Add policy rule scoring (true positives, false positives, bypasses)

**Deliverable:** 100+ rules with efficacy metrics published.

### Week 3: Adversarial Proof (May 5-11)

**Goal:** Prove bypass rate < 10% (vs 57-72% baseline).

**Key Tasks:**
- Build adaptive attacker harness
- Run Stanford Koyejo bypass benchmark
- Recruit external red team ($500 bounty for bypasses)
- Publish known bypasses + regression tests

**Deliverable:** `docs/security/ADVERSARIAL_EVAL.md` with bypass rate < 10%.

### Week 4: Framework Reality (May 12-18)

**Goal:** Ship LangChain + OpenAI adapters to GA.

**Key Tasks:**
- LangChain: Full implementation + installer + tests + docs
- OpenAI Agents: Full implementation + installer + tests + docs
- Adapter conformance test suite (20 tests all adapters must pass)

**Deliverable:** 3 frameworks in GA (Claude Code, LangChain, OpenAI).

### Week 5: Enterprise Operability (May 19-25)

**Goal:** Enable team deployments (5-50 developers).

**Key Tasks:**
- HashiCorp Vault integration (centralized key management)
- Policy bundle versioning (canonical policies, no drift)
- Mission Control team dashboard (aggregate violations)
- RBAC + compliance reporting (SOC2-ready)

**Deliverable:** "Team mode" documented + working.

### Week 6: Proof Packaging (May 26 - June 1)

**Goal:** Zero-friction validation for researchers + enterprises.

**Key Tasks:**
- Finalize + test 10-minute proof runbook (95% success rate)
- Benchmark: MVAR vs baseline runtime (latency, block rate, FP rate)
- Auditor docs: Verification guide, schema reference, guarantees/limits
- Optional: ArXiv preprint submission

**Deliverable:** Researchers can validate all claims in < 1 hour.

---

## Success Metrics (Post-Week 6)

### Quantitative

- ✅ **Bypass rate < 10%** (vs 57-72% baseline)
- ✅ **3 frameworks GA** (Claude Code, LangChain, OpenAI)
- ✅ **100+ policy rules** with test coverage
- ✅ **10-minute proof** - 95% cold user success rate
- ✅ **External validation** - 3+ independent researchers confirm claims

### Qualitative

- ✅ **Honest positioning** - No overclaims, all "firsts" have evidence
- ✅ **Trust signals** - Third-party audit, public red team, published bypasses
- ✅ **Enterprise ready** - Team mode works for 5-50 developers
- ✅ **Effortless validation** - Researchers verify in < 1 hour

---

## The Narrative Shift

### Before (1.5.2 - Today)

**Perception:**
- "Interesting prototype with promising ideas"
- "Need to see production deployment"
- "Unclear if this works beyond Claude Code"
- "No independent validation"

**Reality:**
- Working prototype with 1 production framework
- 23 policy rules (demo quality)
- No adversarial testing
- Self-reported metrics only

### After (1.6.0 - Week 6 Complete)

**Perception:**
- "Validated bypass rate of 8% vs 57-72% baseline"
- "3 frameworks in production, team deployments working"
- "Independent red team + academic validation"
- "Can reproduce all results in 1 hour"

**Reality:**
- Production-ready for teams of 5-50
- 100+ policy rules with efficacy metrics
- Public red team results + known bypasses documented
- Third-party validation confirms claims

**The Shift:** From "impressive build" to "credible category leader with validated claims."

---

## Immediate Next Actions (This Week)

1. **Commit gap closure docs to mvar repo:**
   ```bash
   git add docs/SUPPORT_MATRIX.md \
           docs/security/QSEAL_MODES.md \
           docs/security/PRIOR_ART.md \
           docs/PROOF_RUNBOOK.md \
           docs/GAP_CLOSURE_TRACKER.md
   git commit -m "docs: add gap closure plan and honest positioning"
   ```

2. **Update README.md:**
   - Add "Production Ready: Claude Code" section at top
   - Link to SUPPORT_MATRIX for other frameworks
   - Replace vague multi-framework claims with roadmap

3. **Test proof runbook:**
   - Recruit 2-3 users from Anthropic Discord / X
   - Ask them to run cold (no prior MVAR knowledge)
   - Fix any friction points they encounter

4. **Start Week 2 prep:**
   - Create `docs/security/THREAT_TAXONOMY.md` skeleton
   - Identify first 20 ATT&CK techniques to map
   - Draft policy rule expansion plan (23 → 50 → 100)

---

## Questions for Shawn

1. **Priority:** Do we proceed with this 6-week plan, or pivot to different priorities?

2. **Resources:** Week 3 (red team bounty) will cost ~$500-1000. Week 5 (team mode) requires test environment with multiple developers. Can we resource these?

3. **Academic submission:** Week 6 includes optional ArXiv paper. Worth doing, or premature before more validation?

4. **External validation:** Who are the 3+ independent researchers we want validating claims? Should we proactively recruit them (e.g., Koyejo lab at Stanford)?

5. **Release cadence:** Ship 1.6.0 after Week 6, or incremental releases (1.5.3 for docs, 1.5.4 for policy expansion, etc.)?

---

**Session Duration:** ~2 hours
**Deliverables:** 5 new docs (2,800+ lines), 6-week execution plan, honest positioning corrections
**Status:** Ready to execute Week 1 remaining tasks + Week 2 kickoff

**Next Session:** Test proof runbook with external users, finalize README updates, start threat taxonomy.
