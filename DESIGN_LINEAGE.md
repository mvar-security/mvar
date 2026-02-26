# MVAR: Design Lineage & Prior Art
**Public-facing architectural context (safe for README/HN linking)**

---

## Pattern Class

**PPCI (Provenance + Policy + Cryptographic Integrity)**

A system architecture that:
1. Records derivation lineage (where data came from)
2. Enforces boundary rules at sinks (what's allowed where)
3. Cryptographically seals artifacts and decisions (tamper-evident audit)

---

## Prior Art

MVAR builds on 40+ years of research in formal security methods:

**Information Flow Control (IFC):**
- FIDES (1980s) — lattice-based taint tracking for secure programs
- Jif (2000s) — Java + Information Flow compiler
- FlowCaml (2000s) — ML with static information flow analysis
- **Application:** MVAR uses IFC-style dual lattices (integrity + confidentiality) for conservative taint propagation

**Capability-Based Security:**
- Capsicum (2010) — OS-level capability framework for privilege separation
- **Application:** MVAR uses deny-by-default execution model with target-scoped authority

**Provenance Graphs:**
- Database lineage systems (2000s-2010s) — track data derivation for audit/compliance
- **Application:** MVAR uses append-only provenance graphs with parent pointers for tool-call lineage

**Cryptographic Primitives:**
- Ed25519 (2011) — high-performance elliptic curve signatures
- SHA-256 (2001) — collision-resistant content hashing
- **Application:** MVAR uses QSEAL (Ed25519 + SHA-256) for tamper-evident node signatures

---

## What's New Here

**Contribution:** A runnable, end-to-end enforcement layer implementing IFC-style provenance + policy for LLM tool-call runtimes.

**Domain application:** Existing IFC research focused on static program analysis (compile-time enforcement). MVAR applies these principles to dynamic, model-driven control flow — enforcing information flow constraints at runtime tool execution boundaries.

**Systems integration:** Combines provenance tracking (where), policy enforcement (what's allowed), and cryptographic auditability (proof) into a single coherent runtime layer.

**Zero lock-in:** SDK adapter pattern works with any agent framework (LangChain, OpenAI, custom) — no vendor coupling.

---

## Architectural Analogue

MVAR shares structural primitives with prior work on agent identity continuity:

| Primitive | Identity Continuity (Identity Domain) | MVAR (Execution Domain) |
|-----------|----------------------------|------------------------|
| **Provenance tracking** | Scroll chains (session lineage) | Provenance graphs (tool-call lineage) |
| **Policy enforcement** | Constitutional constraints | Sink policy rules |
| **Cryptographic integrity** | QSEAL signatures on state | QSEAL signatures on nodes + decisions |
| **Conservative propagation** | PAD emotional lattices | Integrity/confidentiality lattices |

**Observation:** Agent identity continuity and agent execution control are structurally analogous problems — both require the same PPCI pattern class. The domain changes (identity vs. execution), but the primitives remain constant.

---

## Explicit Limitations

MVAR Phase 1 has documented architectural boundaries:

**1. Trusted Runtime Assumption**
- If an attacker gains write access to the provenance graph process, they can inject TRUSTED nodes
- Analogous to firewall rule compromise: if you can mutate the enforcement layer itself, you control policy
- Mitigation: QSEAL signature verification at sink time detects post-creation tampering

**2. Composition Attack Semantics**
- Multi-step attack chains (LOW-risk + LOW-risk = HIGH-risk outcome) not modeled in Phase 1
- Each sink evaluated independently, no cross-sink state tracking
- Phase 2 roadmap: inter-sink correlation

**3. Manual Sink Annotation**
- Requires explicit sink registration (not automatic instrumentation)
- Roadmap: adapter hooks for LangChain/OpenAI/LlamaIndex auto-instrumentation
- Same adoption pattern as OpenTelemetry (explicit opt-in → framework-native integration)

---

## Positioning Statement

**What MVAR is:**
- An enforcement layer for information flow control in LLM agent runtimes
- A practical implementation of proven IFC theory applied to a new domain
- A systems integration contribution — applying proven theory to a domain where it hadn't been applied

**What MVAR is not:**
- Not a detection system (it enforces, it doesn't heuristically judge)
- Not a replacement for model safety (it's defense-in-depth infrastructure)
- Not claiming to "solve" all agent security (it mitigates a specific attack class)

---

## References

**Core research foundations:**
- Myers, A. C. (1999). "JFlow: Practical Mostly-Static Information Flow Control." POPL.
- Pottier, F. & Simonet, V. (2003). "Information Flow Inference for ML." TOPLAS.
- Watson, R. N. M., et al. (2010). "Capsicum: Practical Capabilities for UNIX." USENIX Security.
- Sabelfeld, A. & Myers, A. C. (2003). "Language-based Information-Flow Security." IEEE J-SAC.

**Contemporary agent security:**
- OWASP LLM Top 10 (2023-2024) — Prompt injection documented as #1 risk
- Greshake et al. (2023). "Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection."

---

**Status:** Public-facing architectural context document. Safe for README linking, HN discussion, and academic reference.
