---
name: Integration Request
about: Request or propose a first-party integration path for MVAR
title: "[INTEGRATION] "
labels: ["integration", "triage"]
assignees: ""
---

## Integration Target

Which runtime or framework should MVAR integrate with?

- [ ] LangChain / LangGraph
- [ ] OpenAI Agents SDK
- [ ] OpenAI Responses runtime
- [ ] Google ADK
- [ ] MCP server/tooling
- [ ] AutoGen / CrewAI
- [ ] OpenClaw
- [ ] Other:

## Use Case

Describe the exact deployment path and what should be enforced.

## Tool Boundary

Which tool operations are in scope?

- [ ] shell / command execution
- [ ] filesystem writes
- [ ] network egress
- [ ] credential-bearing API calls
- [ ] other:

## Proposed Contract

What should the adapter preserve?

- [ ] deterministic sink outcome (ALLOW/BLOCK/STEP_UP)
- [ ] provenance node continuity into tool calls
- [ ] execution-witness binding semantics
- [ ] trace fields (`policy_hash`, integrity, sink risk)

## Minimal Repro (Optional)

```bash
# minimal commands from clean checkout
```

## Acceptance Criteria

How do we know this integration is done?

- [ ] adapter example added
- [ ] regression test(s) added
- [ ] docs quickstart added
- [ ] launch-gate coverage added (if applicable)

## Contribution Intent

- [ ] I can open a PR
- [ ] I can test a draft PR
- [ ] Request only
