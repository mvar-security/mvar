---
name: OpenAI Break Attempt
about: Submit a reproducible attempt to bypass MVAR on OpenAI integration paths
title: "[OPENAI BREAK ATTEMPT] "
labels: ["security", "openai", "triage"]
assignees: ''
---

## Goal
Describe the bypass attempt clearly. Focus on reproducibility, not speculation.

## Attack Category
- [ ] RAG injection / indirect prompt injection
- [ ] Obfuscation / taint laundering
- [ ] Tool routing confusion
- [ ] Execution-token boundary bypass
- [ ] Principal isolation issue
- [ ] Other:

## Reproduction Commands
Paste exact commands used:

```bash
# Example baseline checks
python examples/agent_testbed.py --scenario rag_injection
python examples/agent_testbed.py --scenario taint_laundering
python examples/agent_testbed.py --scenario benign

# OpenAI deep integration check
pytest -q tests/test_openai_deep_integration.py
```

## Payload / Input
```text
# Paste exact prompt/tool payload/model output
```

## Expected Behavior
- What should MVAR have done?

## Actual Behavior
- What happened instead?

## Evidence
- [ ] Policy outcome and reason captured
- [ ] Evaluation trace captured (`policy_hash`, integrity, sink risk, QSEAL fields)
- [ ] If Docker path used, smoke output included

```text
# Paste relevant logs/traces
```

## Environment
- Commit SHA:
- OS:
- Python version:
- Install method: source / wheel / docker
- Adapter path: OpenAI wrapper / OpenAI responses runtime

## Impact
- [ ] False allow (security risk)
- [ ] False block (usability risk)
- [ ] Invariant mismatch
- [ ] Other:

## Optional PR
- [ ] I can submit a failing test case (preferred)
- [ ] I can submit a fix
