# Week 3 Red Team Outreach Templates

**Date:** April 21, 2026
**Purpose:** Independent validation of MVAR adversarial evaluation methodology
**Timeline:** Send April 22-28, validation window May 1-10

---

## 1. Sanmi Koyejo — Email

**To:** sanmi@cs.stanford.edu (or via Stanford CS directory)

**Subject:** Methodology review request — adversarial evaluation for LLM agent policy enforcement

Hi Sanmi,

Your lab's AutoRedTeamer work and the broader Trustworthy AI Research Lab findings on model-level guardrail bypass rates (57-72%) have been a reference point as I've been building MVAR, an information flow control enforcement boundary for LLM agents at the tool-call layer.

I've just completed initial adversarial evaluation with a methodology I'd value your read on.

The short version: baseline policy showed 86.2% bypass rate against encoding attacks. After encoding-aware evaluation was added, controlled A/B re-measurement came in at 0.2% bypass, 0% false positive, sub-millisecond latency. Methodology and results are published at github.com/mvar-security/mvar under docs/security/.

The narrow ask: would you have 20 minutes to look at the evaluation protocol (`docs/security/EVALUATION_PROTOCOL.md`) and tell me what's missing or methodologically weak? I'm particularly unsure about whether the 10-variant semantic-preservation set is sufficient coverage, and whether comparison to unprotected baseline is the right reference point vs. comparing to guardrail products directly.

Apache 2.0, public repo, reproducible from the command lines in the docs. Not asking for a broad review — just methodology critique before I socialize the numbers more widely.

Happy to take this to 0 or 30 minutes as fits your schedule.

— Shawn Cohen
shawn@mvar.io
github.com/mvar-security/mvar

---

## 2. Florian Tramèr — Email

**To:** tramer@inf.ethz.ch

**Subject:** Variant generation critique — adversarial harness for LLM agent policy enforcement

Hi Florian,

Your work on adaptive adversaries and membership inference attacks has been the mental model I've been holding while building MVAR's adversarial evaluation harness. I'm writing because I think the harness I've built may be naive compared to the state of the art, and I'd value a direct read.

Context: MVAR is an information flow control enforcement layer for LLM agents at the tool-call boundary, with cryptographic decision audit. The adversarial harness generates 10 variant types per base attack (base64, hex, command substitution, quoting, paths, whitespace, env vars, redirects, globs, logical operators) and measures bypass rate against the policy engine.

Initial measurement showed 86.2% bypass against encoding attacks. After encoding-aware evaluation was added to the engine, clean A/B re-measurement came in at 0.2% bypass with zero false positives.

The narrow ask: would you have 20 minutes to look at `tests/adversarial/adaptive_attacker.py` and the associated corpus, and tell me whether this variant generation approach is as weak as I suspect? I'm particularly concerned that 10 transformation types per attack is a toy adversary, and that a properly adaptive attacker would exploit the patch quickly.

If the answer is "this harness is insufficient, you need X," that's exactly what I need to hear before we ship 1.5.4.

Apache 2.0, public repo: github.com/mvar-security/mvar

— Shawn Cohen
shawn@mvar.io

---

## 3. Harrison Chase — Email

**To:** harrison@langchain.dev (or via LangChain contact channels)

**Subject:** Pre-ship check — MVAR LangChain adapter architecture

Hi Harrison,

Building an open-source cryptographic policy enforcement layer for LLM agents. Claude Code integration is shipping now. LangChain adapter is targeted for mid-May.

The short version: MVAR wraps tool-calling at the framework boundary with policy evaluation and HMAC-signed audit records. For LangChain, that means intercepting tool invocations, evaluating against policy, and emitting signed decisions to a dashboard — without forcing users to restructure their agent code.

The narrow ask: could I get 15 minutes before we ship the LangChain adapter to make sure I'm wrapping the framework idiomatically? Specifically, whether the callback handler pattern is the right integration point or whether there's a more canonical approach I'm missing. I'd rather ask before shipping than get corrected publicly after.

Current state is at github.com/mvar-security/mvar. Claude Code adapter in `mvar/adapters/claude_code.py` shows the pattern I'm planning to replicate for LangChain.

Any preference on format — email exchange, brief call, or GitHub issue thread?

— Shawn Cohen
shawn@mvar.io

---

## 4. OpenAI Agents Team — GitHub Issue

**Post as an issue on:** github.com/openai/openai-agents-python or equivalent repo

**Title:** Pre-adapter-ship question — OpenAI Agents integration point for third-party policy enforcement

Building MVAR, an open-source information flow control enforcement layer for LLM agents. OpenAI Agents adapter is on our roadmap for post-1.6.0.

Before I build the adapter, wanted to ask the maintainers: what's the canonical integration point for third-party tool-call interception in OpenAI Agents? The goal is to wrap agent tool invocations with a policy evaluation step that can allow, block, or audit — ideally without forking the framework.

Current reference implementation is our Claude Code adapter at github.com/mvar-security/mvar/blob/main/mvar/adapters/claude_code.py (Apache 2.0). Happy to match the pattern you'd prefer rather than guess.

If there's a standard hook point, documented extension mechanism, or existing pattern for this, pointing me to it would save me shipping something awkward.

Thanks,
Shawn Cohen / shawn@mvar.io

---

## 5. LangChain Security Lead — GitHub Issue or Discussion

**Post on:** github.com/langchain-ai/langchain/discussions

**Title:** Feedback request — third-party policy enforcement adapter for LangChain agents

Building an open-source policy enforcement layer for LLM agents (MVAR, github.com/mvar-security/mvar, Apache 2.0). The LangChain adapter is targeted for mid-May.

Before shipping, I'd value the security team's read on two things:

One — Integration point. Planning to use the callback handler pattern to intercept tool invocations, evaluate against policy, and emit signed decisions. Is this the right hook, or is there a more appropriate integration point for tool-call-level policy enforcement?

Two — Adversarial evaluation methodology. We just completed an A/B measurement showing 86.2% bypass on the baseline policy dropping to 0.2% after encoding-aware evaluation was added. Full methodology at `docs/security/ADVERSARIAL_EVAL.md`. Would appreciate any feedback on whether the variant generation approach is representative of real attacks against LangChain agents specifically.

Open to any format — comments on this discussion, GitHub issue, direct contact. Whatever is easiest for the team.

— Shawn Cohen

---

## 6. Broader Security Community — Discord/Slack Post

**Post in:** Claude Code Discord #security channel, LangChain Discord #security, or equivalent community spaces

Hey all — looking for 3-5 independent red-teamers for MVAR before we ship 1.5.4.

What is it: Open-source information flow control enforcement for LLM agents at the tool-call layer, with cryptographic audit. Claude Code integration shipping, LangChain mid-May.

What I need validated:

- Reproducibility of the bypass rate measurements (86.2% baseline → 0.2% post-patch)
- Whether the variant generation in our adaptive attacker is actually adversarial or naive
- False positive pressure against real developer workflows (the benign corpus has 100 commands, may be too narrow)
- Whether the residual 0.2% bypass is correctly classified

Time commitment: Probably 1-2 hours to run the harness, look at methodology, and write back with findings. Happy to credit contributors in the release notes.

Materials: github.com/mvar-security/mvar — docs/security/RED_TEAM_INVITATION_PACKAGE.md has the full ask and repro commands.

DM me if interested.

— Shawn

---

## 7. Twitter/X DM Version — For Anyone with a Smaller Audience Window

**Use for:** Security practitioners with Twitter presence but no direct email access

Hey [Name] — building open-source policy enforcement for LLM agents (mvar-security on PyPI, Apache 2.0). Just measured 86.2% → 0.2% bypass rate improvement after encoding-aware evaluation. Need independent red-team validation of the methodology before shipping 1.5.4.

Full package at github.com/mvar-security/mvar/blob/main/docs/security/RED_TEAM_INVITATION_PACKAGE.md.

Would you have 30 minutes? Small ask: just tell me what's weak about the variant generation or evaluation protocol. Not asking you to share or endorse.

Shawn

---

## 8. Warm Intro One-Liner — For Any Mutual Connection

**Use when someone offers to make an intro**

"Building open-source policy enforcement for LLM agents. Just finished adversarial evaluation showing 86.2% → 0.2% bypass improvement. Need a few independent eyes on the methodology before shipping. Looking for 30-minute reviews, not broad endorsements. Would love an intro if you know anyone who'd be interested."

---

## Sending Schedule

**April 22 (tomorrow):**
- Template 1 (Sanmi Koyejo)
- Template 2 (Florian Tramèr)
- Template 3 (Harrison Chase)

**April 22-23:**
- Template 4 (OpenAI Agents GitHub issue)
- Template 5 (LangChain Security discussion)

**April 23-28:**
- Template 6 (Discord/Slack posts)
- Template 7 (Twitter DMs to identified targets)
- Template 8 (as warm intro opportunities arise)

**Validation Window:** May 1-10, 2026

---

**Status:** Week 2 complete. All templates ready for Week 3 outreach.
