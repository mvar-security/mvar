# HN Comment Template

Thanks for the early reads.

We added a reproducible baseline-vs-enforced trilogy and made it CI-enforced:
- `rag_injection`: baseline executes, MVAR blocks
- `taint_laundering`: baseline executes, MVAR blocks
- `benign`: both allow

Also shipped Milestone 1 OpenAI deep integration:
- OpenAI multi-tool runtime (`mvar_openai`)
- Docker cookbook + smoke assertions
- CI gate for OpenAI deep integration

Repro:
```bash
python examples/agent_testbed.py --scenario rag_injection
python examples/agent_testbed.py --scenario taint_laundering
python examples/agent_testbed.py --scenario benign
python3 ./scripts/check_agent_testbed_trilogy.py
pytest -q tests/test_openai_deep_integration.py
```

Links:
- Trilogy artifact: https://github.com/mvar-security/mvar/blob/main/docs/MVAR_AGENT_TESTBED_TRILOGY.md
- OpenAI cookbook: https://github.com/mvar-security/mvar/blob/main/docs/deployment/OPENAI_DOCKER_COOKBOOK.md
- Workflow: https://github.com/mvar-security/mvar/actions/workflows/launch-gate.yml

If you can break the OpenAI path, please file it with repro steps. We prioritize failing regression tests.
