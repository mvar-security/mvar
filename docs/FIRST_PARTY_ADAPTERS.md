# First-Party Adapter Wrappers

MVAR now includes first-party adapter wrappers for common agent ecosystems.

## Install (Adapters Included)

Adapters are shipped with the main `mvar` package. There is no separate adapter package to install.

Install from source (recommended while developing):

```bash
git clone https://github.com/mvar-security/mvar.git
cd mvar
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip setuptools wheel
python -m pip install . pytest
```

Or install published package version:

```bash
pip install mvar-security
```

Quick import check:

```bash
python -c "from mvar_adapters import MVARMCPAdapter; print('adapter import ok')"
```

Framework note:
- MVAR adapters wrap your existing agent stack.
- Install the framework SDK(s) you already use (for example LangChain/OpenAI/CrewAI/MCP/Anthropic/Google ADK).
- Package names vary by ecosystem; use your framework's install docs.

Full install guide: [../INSTALL.md](../INSTALL.md)

## Adapter Code + Quickstart Map

| Adapter | Wrapper Class | Source Code | Quickstart |
|---|---|---|---|
| LangChain | `MVARLangChainAdapter` | [`../mvar_adapters/langchain.py`](../mvar_adapters/langchain.py) | [`../examples/adapters/langchain_quickstart.py`](../examples/adapters/langchain_quickstart.py) |
| OpenAI tool calling | `MVAROpenAIAdapter` | [`../mvar_adapters/openai.py`](../mvar_adapters/openai.py) | [`../examples/adapters/openai_quickstart.py`](../examples/adapters/openai_quickstart.py) |
| MCP | `MVARMCPAdapter` | [`../mvar_adapters/mcp.py`](../mvar_adapters/mcp.py) | [`../examples/adapters/mcp_quickstart.py`](../examples/adapters/mcp_quickstart.py) |
| Claude tool runtime | `MVARClaudeToolAdapter` | [`../mvar_adapters/claude.py`](../mvar_adapters/claude.py) | Use `MVARClaudeToolAdapter` via your tool-dispatch layer |
| AutoGen | `MVARAutoGenAdapter` | [`../mvar_adapters/autogen.py`](../mvar_adapters/autogen.py) | [`../examples/adapters/autogen_quickstart.py`](../examples/adapters/autogen_quickstart.py) |
| CrewAI | `MVARCrewAIAdapter` | [`../mvar_adapters/crewai.py`](../mvar_adapters/crewai.py) | [`../examples/adapters/crewai_quickstart.py`](../examples/adapters/crewai_quickstart.py) |
| OpenClaw | `MVAROpenClawAdapter` | [`../mvar_adapters/openclaw.py`](../mvar_adapters/openclaw.py) | [`../examples/adapters/openclaw_quickstart.py`](../examples/adapters/openclaw_quickstart.py) |
| Google ADK | `MVARGoogleADKAdapter` | [`../mvar_adapters/google_adk.py`](../mvar_adapters/google_adk.py) | [`../examples/adapters/google_adk_quickstart.py`](../examples/adapters/google_adk_quickstart.py) |
| OpenAI Agents SDK | `MVAROpenAIAgentsAdapter` | [`../mvar_adapters/openai_agents.py`](../mvar_adapters/openai_agents.py) | [`../examples/adapters/openai_agents_quickstart.py`](../examples/adapters/openai_agents_quickstart.py) |

Related runtime wrappers:

- OpenAI Responses runtime: [`../examples/adapters/openai_responses_runtime_quickstart.py`](../examples/adapters/openai_responses_runtime_quickstart.py)
- OpenClaw runtime: [`../examples/adapters/openclaw_runtime_quickstart.py`](../examples/adapters/openclaw_runtime_quickstart.py)

## Included wrappers

- `mvar_adapters.langchain.MVARLangChainAdapter`
- `mvar_adapters.openai.MVAROpenAIAdapter`
- `mvar_adapters.mcp.MVARMCPAdapter`
- `mvar_adapters.claude.MVARClaudeToolAdapter`
- `mvar_adapters.autogen.MVARAutoGenAdapter`
- `mvar_adapters.crewai.MVARCrewAIAdapter`
- `mvar_adapters.openclaw.MVAROpenClawAdapter`
- `mvar_adapters.google_adk.MVARGoogleADKAdapter`
- `mvar_adapters.openai_agents.MVAROpenAIAgentsAdapter`

All wrappers enforce the same default boundary:

- Evaluate sink policy first
- Authorize execution with execution-token checks
- Block execution when policy denies
- Do not execute on `STEP_UP` unless explicitly enabled

Quickstart examples:
- `mvar_adapters/README.md`
- `examples/adapters/langchain_quickstart.py`
- `examples/adapters/openai_quickstart.py`
- `examples/adapters/openai_responses_runtime_quickstart.py`
- `examples/adapters/mcp_quickstart.py`
- `examples/adapters/autogen_quickstart.py`
- `examples/adapters/crewai_quickstart.py`
- `examples/adapters/openclaw_quickstart.py`
- `examples/adapters/google_adk_quickstart.py`
- `examples/adapters/openai_agents_quickstart.py`
- `examples/adapters/openclaw_runtime_quickstart.py`

## Example: OpenAI tool call wrapper

```python
from mvar_adapters import MVAROpenAIAdapter

adapter = MVAROpenAIAdapter(policy, graph, strict=True)
result = adapter.execute_tool_call(tool_call, tool_registry, source_text="model output")
```

## Milestone 1: Deeper OpenAI Runtime (Responses + Multi-Tool)

For OpenAI response payloads containing multiple tool calls, use the deeper runtime:

```python
from mvar_openai import MVAROpenAIResponsesRuntime

runtime = MVAROpenAIResponsesRuntime(policy, graph, strict=False)
turn_node = runtime.create_turn_provenance(
    user_prompt="Summarize retrieved docs",
    retrieved_chunks=["external chunk"],
)
batch = runtime.execute_response(
    response_payload=response_payload,
    tool_registry=tool_registry,
    provenance_node_id=turn_node,
    source_context="user_prompt + retrieved_doc_chunk",
    planner_output="model proposed tool plan",
)
```

This runtime adds:
- multi-tool dispatch from one model response
- conservative provenance composition for user + retrieval context
- context markers (`source_context`, `planner_output`) appended to decision traces

## Example: MCP wrapper

```python
from mvar_adapters import MVARMCPAdapter

adapter = MVARMCPAdapter(policy, graph, strict=True)
result = adapter.execute_mcp_request(request, tool_registry, source_text="external input", source_is_untrusted=True)
```

## Security note

These wrappers are thin execution-boundary guards and should be used as the only path to privileged sink execution in adapter code.

For required integration rules, see:
- `docs/ADAPTER_SPEC.md`
- `conformance/pytest_adapter_harness.py`
