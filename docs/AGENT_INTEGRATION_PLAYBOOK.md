# MVAR Agent Integration Playbook

This guide answers two practical questions:

1. Where do I install MVAR?
2. Where do I hook MVAR in an agent runtime?

## Install Location (Always)

Install MVAR in the same runtime environment as the agent process that executes tools.

```bash
pip install mvar
```

If the agent runs in Docker/Kubernetes, install MVAR in that image/container.

## Hook Location (Always)

Hook MVAR at tool execution boundaries:

- before shell/process execution
- before HTTP egress
- before filesystem writes
- before credential access

Do not rely on prompt-time filtering as the enforcement point.

## Common Integration Pattern

1. Build MVAR control plane (`ProvenanceGraph`, `CapabilityRuntime`, `SinkPolicy`).
2. Wrap framework tool dispatch with an MVAR adapter.
3. Route privileged calls only through wrapper codepaths.
4. Block direct sink execution outside adapters.

## Framework Integrations

### OpenClaw

Use `MVAROpenClawAdapter`.

```python
from mvar_adapters import MVAROpenClawAdapter

adapter = MVAROpenClawAdapter(policy, graph, strict=True)
dispatch = {"tool": "bash", "action": "exec", "args": {"command": "echo hello"}}

result = adapter.execute_tool_dispatch(
    dispatch=dispatch,
    tool_registry={"bash": run_shell},
    source_text="OpenClaw planner output",
    source_is_untrusted=True,
)
```

Hook point: OpenClaw tool router used by the agent loop.

### LangChain

Use `MVARLangChainAdapter`.

```python
from mvar_adapters import MVARLangChainAdapter

adapter = MVARLangChainAdapter(policy, graph, strict=True)
safe_tool = adapter.wrap_tool("bash", run_shell, action="exec")
```

Hook point: tool callable registration.

### OpenAI Tool Calling

Use `MVAROpenAIAdapter`.

```python
from mvar_adapters import MVAROpenAIAdapter

adapter = MVAROpenAIAdapter(policy, graph, strict=True)
result = adapter.execute_tool_call(tool_call, tool_registry, source_text="model output")
```

Hook point: function/tool dispatch handler.

For OpenAI Responses API or batches containing multiple tool calls, use `MVAROpenAIResponsesRuntime`:

```python
from mvar_openai import MVAROpenAIResponsesRuntime

runtime = MVAROpenAIResponsesRuntime(policy, graph, strict=False)
turn_node = runtime.create_turn_provenance(
    user_prompt="Summarize these retrieved docs",
    retrieved_chunks=["external chunk"],
)
batch = runtime.execute_response(
    response_payload=response_payload,
    tool_registry=tool_registry,
    provenance_node_id=turn_node,
    source_context="user_prompt + retrieved_doc_chunk",
    planner_output="model-proposed tool plan",
)
```

Hook point: centralized response/tool-call dispatch loop.

### MCP

Use `MVARMCPAdapter`.

```python
from mvar_adapters import MVARMCPAdapter

adapter = MVARMCPAdapter(policy, graph, strict=True)
result = adapter.execute_mcp_request(request, tool_registry, source_text="external request", source_is_untrusted=True)
```

Hook point: `tools/call` request handler.

### Claude tool_use

Use `MVARClaudeToolAdapter`.

```python
from mvar_adapters import MVARClaudeToolAdapter

adapter = MVARClaudeToolAdapter(policy, graph, strict=True)
result = adapter.execute_tool_use(tool_use, tool_registry, source_text="tool_use payload", source_is_untrusted=True)
```

Hook point: tool_use event dispatch path.

### AutoGen

Use `MVARAutoGenAdapter`.

```python
from mvar_adapters import MVARAutoGenAdapter

adapter = MVARAutoGenAdapter(policy, graph, strict=True)
result = adapter.execute_tool_call(tool_call, tool_registry, source_text="model output")
```

### CrewAI

Use `MVARCrewAIAdapter`.

```python
from mvar_adapters import MVARCrewAIAdapter

adapter = MVARCrewAIAdapter(policy, graph, strict=True)
safe_tool = adapter.wrap_tool("bash", run_shell, action="exec")
result = safe_tool({"command": "echo hello"}, source_text="agent output", source_is_untrusted=True)
```

### Other Frameworks

For unsupported frameworks, adapt through `MVARExecutionAdapter` and map runtime payload fields to `tool/action/target/parameters`.

## What Not To Do

- Do not execute tools directly from model output paths.
- Do not call only `policy.evaluate(...)` and skip `authorize_execution(...)`.
- Do not degrade to permissive behavior on policy/token errors.
- Do not share principal identity across unrelated users/tenants.

## Production Checklist

- `strict=True` in adapters.
- `MVAR_REQUIRE_EXECUTION_TOKEN=1`.
- adapter conformance tests passing.
- sink registration coverage checks passing.
- launch/security gate passing.

## Related Docs

- `docs/ADAPTER_SPEC.md`
- `docs/FIRST_PARTY_ADAPTERS.md`
- `docs/deployment/OPENAI_DOCKER_COOKBOOK.md`
- `mvar_adapters/README.md`
- `conformance/pytest_adapter_harness.py`
