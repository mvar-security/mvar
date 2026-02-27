# Reddit Post Template

Title:
MVAR: deterministic sink enforcement for OpenAI/LangChain agents (Docker + CI validated)

Body:
We open-sourced MVAR, a runtime control plane for agent tool execution.

What is currently reproducible:
- Baseline vs enforced trilogy:
  - `rag_injection` -> blocked under MVAR
  - `taint_laundering` -> blocked under MVAR
  - `benign` -> allowed under MVAR
- OpenAI Milestone 1:
  - deeper multi-tool runtime (`mvar_openai`)
  - Docker deployment cookbook
  - CI gate with Docker smoke assertions

Quick repro:
```bash
python examples/agent_testbed.py --scenario rag_injection
python examples/agent_testbed.py --scenario taint_laundering
python examples/agent_testbed.py --scenario benign
python3 ./scripts/check_agent_testbed_trilogy.py
pytest -q tests/test_openai_deep_integration.py
```

Docs:
- README: https://github.com/mvar-security/mvar
- Trilogy artifact: https://github.com/mvar-security/mvar/blob/main/docs/MVAR_AGENT_TESTBED_TRILOGY.md
- OpenAI Docker cookbook: https://github.com/mvar-security/mvar/blob/main/docs/deployment/OPENAI_DOCKER_COOKBOOK.md

Technical critique and break attempts are welcome.
