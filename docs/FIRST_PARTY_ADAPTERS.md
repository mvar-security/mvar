# First-Party Adapter Wrappers

MVAR now includes first-party adapter wrappers for common agent ecosystems.

## Included wrappers

- `mvar_adapters.langchain.MVARLangChainAdapter`
- `mvar_adapters.openai.MVAROpenAIAdapter`
- `mvar_adapters.mcp.MVARMCPAdapter`
- `mvar_adapters.claude.MVARClaudeToolAdapter`
- `mvar_adapters.autogen.MVARAutoGenAdapter`
- `mvar_adapters.crewai.MVARCrewAIAdapter`
- `mvar_adapters.openclaw.MVAROpenClawAdapter`

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
