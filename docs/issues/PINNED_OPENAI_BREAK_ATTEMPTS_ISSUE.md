# Pinned Issue Draft: Call for OpenAI Break Attempts

Use this as the body for a pinned GitHub issue.

## Suggested title
`Call for OpenAI Adapter Break Attempts (Milestone 1)`

## Suggested body
We just shipped Milestone 1 for deeper OpenAI integration.

What is now CI-enforced on every push/PR:
- Launch gate (`./scripts/launch-gate.sh`)
- Trilogy regression gate (`scripts/check_agent_testbed_trilogy.py`)
- OpenAI deep integration tests (`tests/test_openai_deep_integration.py`)
- Docker smoke assertions (`total_calls=2`, `executed_calls=1`, `blocked_calls=1`)

If you can break the OpenAI path, we want the repro.

### Repro baseline
```bash
python examples/agent_testbed.py --scenario rag_injection
python examples/agent_testbed.py --scenario taint_laundering
python examples/agent_testbed.py --scenario benign
pytest -q tests/test_openai_deep_integration.py
```

### What to submit
- Exact payload/prompt and tool-call structure
- Exact commands run
- Expected vs actual behavior
- Trace fields (`policy_hash`, integrity/sink labels, decision reason, QSEAL fields)
- Commit SHA and runtime environment

Please open issues using: `.github/ISSUE_TEMPLATE/openai_break_attempt.md`

If you can provide a failing regression test, that is preferred and will be prioritized.
