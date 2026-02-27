# Maintainer DM Template

Hi <name> — I built MVAR, a deterministic control-plane layer for agent tool execution.

Recent milestone:
- OpenAI deep integration runtime (`mvar_openai`)
- Docker deployment cookbook
- CI-enforced regression checks (trilogy + OpenAI smoke)

Quick repro (local):
```bash
python examples/agent_testbed.py --scenario rag_injection
python examples/agent_testbed.py --scenario taint_laundering
python examples/agent_testbed.py --scenario benign
pytest -q tests/test_openai_deep_integration.py
```

If you have 10 minutes, I’d value a technical critique, especially on bypass paths.

Repo: https://github.com/mvar-security/mvar
OpenAI cookbook: https://github.com/mvar-security/mvar/blob/main/docs/deployment/OPENAI_DOCKER_COOKBOOK.md
