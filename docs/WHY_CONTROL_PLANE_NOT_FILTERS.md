# Why Prompt Injection Is a Control-Plane Problem, Not a Filtering Problem

Prompt injection defense fails when it relies on content guessing alone.

## Core claim
Prompt injection is fundamentally a control-plane problem:
- untrusted content influences model output
- model output requests privileged sink execution
- runtime must enforce deterministic policy at execution boundaries

Content filters can reduce noise, but they cannot be the primary boundary for privileged actions.

## Why filters are insufficient
1. Attackers continuously mutate payload shape (encoding, paraphrase, multi-step indirection).
2. Detection confidence is probabilistic; security boundaries require deterministic outcomes.
3. The same intent can appear in many syntactic forms across tool-call payloads.
4. Mixed-trust context (user + retrieved content) requires provenance-aware decisions.

## Control-plane model used by MVAR
1. Label inputs with integrity/confidentiality provenance.
2. Propagate labels conservatively through derived outputs.
3. Classify sinks by risk (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
4. Enforce deterministic sink policy.
5. Authorize execution with token-bound checks and fail-closed semantics.

Invariant example:
- `UNTRUSTED + CRITICAL -> BLOCK`

## Practical outcome
This approach allows:
- deterministic block on critical untrusted execution paths
- preservation of benign low-risk operations
- auditable traces (`policy_hash`, label checks, sink classification, QSEAL fields)

## Scope discipline
MVAR does not claim completeness against all possible attacks.
It claims deterministic enforcement under defined sink registration, labeling, and policy assumptions.

## Repro references
- Trilogy proof: `docs/MVAR_AGENT_TESTBED_TRILOGY.md`
- Showcase summary: `docs/ATTACK_VALIDATION_SHOWCASE.md`
- OpenAI deployment cookbook: `docs/deployment/OPENAI_DOCKER_COOKBOOK.md`
