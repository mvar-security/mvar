# Prior Art & Positioning

**Last Updated:** 2026-04-21

This document maps MVAR's positioning relative to prior academic work, open source projects, and commercial products. Our goal is to be technically precise about what exists and what MVAR contributes.

---

## Academic Work

| Paper | Year | Authors | Key Contribution | What MVAR Adds |
|-------|------|---------|------------------|----------------|
| **CaMeL: Capabilities Across ML** | 2024 | DeepMind | Formal IFC model for AI agents with capability lattices | Working implementation + cryptographic audit + tool integration |
| **Design Patterns for Securing LLM Applications** | 2024 | OpenAI, Anthropic, others | Catalog of security patterns including input validation and capability control | Enforcement runtime at tool-call boundary + signed decision ledger |
| **PromptBreeder** | 2023 | Google DeepMind | Automated adversarial prompt generation | Adaptive attacker harness (planned 1.6.0) for bypass testing |
| **Universal and Transferable Attacks on Aligned LLMs** | 2023 | CMU, Berkeley | Demonstrates guardrail bypass techniques | Execution-boundary enforcement (not model-level filtering) |

**Summary:** Academic work provides theoretical foundations (IFC models, attack taxonomies, security patterns). MVAR provides a working enforcement runtime with cryptographic provenance that can be installed and used today.

---

## Open Source Projects

### Direct Comparison (Agent Security)

| Project | Maintained By | Approach | Enforcement Point | Audit Trail | What MVAR Adds |
|---------|--------------|----------|-------------------|-------------|----------------|
| **NeMo Guardrails** | NVIDIA | LLM output filtering | Model output | Logs (unsigned) | Tool-call boundary + IFC enforcement + cryptographic signing |
| **LangChain Security** | LangChain AI | Tool validation + logging | Pre-tool-call | Logs (unsigned) | Policy engine + signed decisions + Mission Control visibility |
| **OpenClaw Skill Scanner** | OpenClaw | Static analysis of tool definitions | Install-time | Scan reports | Runtime enforcement + dynamic policy + decision audit |
| **LLM Guard** | Community | Content filtering (PII, toxicity) | Input/output | Logs (unsigned) | Execution-boundary IFC + tool-specific policies |
| **Guardrails AI** | Community | Output validation + correction | Model output | Logs (unsigned) | Execution enforcement + cryptographic provenance |

**Key Differentiation:**
- **Enforcement point:** Tool-call boundary (MVAR) vs model output (NeMo/Guardrails AI) vs pre-call validation (LangChain)
- **Audit:** Cryptographically signed decisions (MVAR) vs unsigned logs (others)
- **Policy model:** IFC lattice with provenance tracking (MVAR) vs rule-based filtering (others)

### Adjacent Projects (Supply Chain / Observability)

| Project | Focus | Relevance to MVAR |
|---------|-------|-------------------|
| **Langfuse** | LLM observability | Complements MVAR - observes traces, MVAR enforces decisions |
| **LangSmith** | LLM debugging | Complements MVAR - debugging tool, not enforcement |
| **OpenTelemetry** | Distributed tracing | MVAR uses OpenTelemetry for observability exports |
| **Sigstore** | Artifact signing | Could integrate for policy bundle signing (future) |

---

## Commercial Products

| Product | Company | Approach | Deployment | Pricing | What MVAR Adds |
|---------|---------|----------|------------|---------|----------------|
| **Prisma AIRS** | Palo Alto Networks | Enterprise guardrails + DLP | Cloud/on-prem | $$$$ Enterprise | Open source + tool-call IFC + crypto audit |
| **Protect AI Guardian** | Protect AI | Model-level monitoring + scanning | Cloud SaaS | $$ Team | Execution-boundary enforcement + local-first |
| **HiddenLayer AI Scanner** | HiddenLayer | ML model scanning | Cloud SaaS | $$ Team | Runtime enforcement (not static scan) |
| **Calypso AI** | Calypso | AI governance platform | Enterprise | $$$$ Enterprise | Lightweight runtime + open source |
| **Arthur AI** | Arthur Shield | Model monitoring + guardrails | Cloud SaaS | $$$ Enterprise | Tool-call IFC + crypto provenance |

**Key Differentiation:**
- **Cost:** MVAR is free and open source vs $10k-$100k+ annual licenses
- **Deployment:** Local-first (MVAR) vs cloud-only SaaS (most commercial)
- **Enforcement:** Tool-call boundary IFC vs model-level filtering
- **Audit:** Cryptographic signing (MVAR) vs standard logs (most commercial)

---

## Our Precise Positioning

### The Claim

> **"MVAR is the first open-source, installable information flow control enforcement runtime for LLM agents with cryptographic decision audit at the tool-call boundary."**

### Why Each Word Matters

| Qualifier | Excludes | Examples Excluded |
|-----------|----------|-------------------|
| **Open source** | Proprietary commercial products | Prisma AIRS, Protect AI Guardian, Arthur Shield |
| **Installable** | Academic papers without implementation | CaMeL (formal model only), Design Patterns (guidelines) |
| **Information flow control** | Simple filtering/detection | LLM Guard (content filter), Langfuse (observability) |
| **Enforcement runtime** | Static analysis tools | OpenClaw Skill Scanner (install-time check) |
| **LLM agents** | General ML model security | HiddenLayer (model scanning), not agent-specific |
| **Cryptographic decision audit** | Unsigned logging | LangChain Security, NeMo Guardrails (plain logs) |
| **Tool-call boundary** | Model-level guardrails | NeMo Guardrails, Guardrails AI (output filtering) |

### What We Don't Claim

❌ **"First IFC for AI systems"** - IFC has been applied to ML in academic settings
❌ **"First agent security tool"** - Many exist (NeMo, LangChain Security, OpenClaw)
❌ **"First cryptographic audit for AI"** - Model provenance signing exists
❌ **"Only solution to prompt injection"** - No solution prevents all prompt injection

✅ **What we do claim:** First production-ready, open-source IFC enforcement + crypto audit specifically at the agent tool-call boundary

---

## Competitive Matrix

### Feature Comparison

| Feature | MVAR | NeMo Guardrails | LangChain Security | Prisma AIRS | OpenClaw Scanner |
|---------|------|-----------------|-------------------|-------------|------------------|
| **Open Source** | ✅ | ✅ | ✅ | ❌ | ✅ |
| **IFC Enforcement** | ✅ | ❌ | ❌ | Partial | ❌ |
| **Tool-Call Boundary** | ✅ | ❌ | Partial | ✅ | ❌ |
| **Crypto Signing** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **One-Command Install** | ✅ | ✅ | ✅ | ❌ | ✅ |
| **Framework Agnostic** | Planned | ❌ | ✅ | ✅ | ✅ |
| **Self-Hosted** | ✅ | ✅ | ✅ | Optional | ✅ |
| **Adaptive Testing** | Planned | ❌ | ❌ | Unknown | ❌ |

---

## Academic Citations

If you cite MVAR in academic work, please cite:

```bibtex
@software{mvar2026,
  author = {Cohen, Shawn},
  title = {MVAR: Information Flow Control for LLM Agent Runtimes},
  year = {2026},
  url = {https://github.com/mvar-security/mvar},
  note = {Open-source IFC enforcement with cryptographic audit}
}
```

**Prior work we build upon:**

- Denning, D. E. (1976). "A Lattice Model of Secure Information Flow" - Foundational IFC theory
- Myers, A. C. (1999). "JFlow: Practical Mostly-Static Information Flow Control" - IFC for programming languages
- Koyejo, S. et al. (2024). "Adversarial Robustness of ML Guardrails" - Bypass testing methodology
- Anthropic (2024). "Design Patterns for Securing LLM Applications" - Agent security catalog

---

## Feedback & Corrections

If you know of prior work we've missed or if any positioning is inaccurate:

1. Open an issue: https://github.com/mvar-security/mvar/issues
2. Email: security@mvar.io
3. Submit a PR updating this document

We want to be technically precise and give proper credit to all prior work.

**Last reviewed:** 2026-04-21
