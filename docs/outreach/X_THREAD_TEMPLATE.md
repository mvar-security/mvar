# X Thread Template

1/ Shipped Milestone 1 for MVAR (deterministic sink enforcement for agent runtimes).

2/ Repro trilogy (baseline vs enforced):
- rag_injection: baseline executes, MVAR blocks
- taint_laundering: baseline executes, MVAR blocks
- benign: both allow

3/ We now CI-enforce this behavior on every push/PR.

4/ Also shipped deeper OpenAI integration:
- multi-tool runtime (`mvar_openai`)
- Docker deployment cookbook
- Docker smoke assertions in CI (`total_calls=2`, `executed_calls=1`, `blocked_calls=1`)

5/ Repro:
```bash
python examples/agent_testbed.py --scenario rag_injection
python examples/agent_testbed.py --scenario taint_laundering
python examples/agent_testbed.py --scenario benign
python3 ./scripts/check_agent_testbed_trilogy.py
pytest -q tests/test_openai_deep_integration.py
```

6/ Links:
- Repo: https://github.com/mvar-security/mvar
- Trilogy: https://github.com/mvar-security/mvar/blob/main/docs/MVAR_AGENT_TESTBED_TRILOGY.md
- OpenAI cookbook: https://github.com/mvar-security/mvar/blob/main/docs/deployment/OPENAI_DOCKER_COOKBOOK.md

7/ If you can break the OpenAI path with a clean repro, open an issue. Failing regression tests get priority.
