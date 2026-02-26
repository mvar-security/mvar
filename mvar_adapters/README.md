# MVAR Adapter Quickstart

This folder contains first-party wrappers for common agent/tool ecosystems:

- `langchain.py` → `MVARLangChainAdapter`
- `openai.py` → `MVAROpenAIAdapter`
- `mcp.py` → `MVARMCPAdapter`
- `claude.py` → `MVARClaudeToolAdapter`
- `autogen.py` → `MVARAutoGenAdapter`
- `crewai.py` → `MVARCrewAIAdapter`
- `openclaw.py` → `MVAROpenClawAdapter`

These wrappers enforce the execution boundary by default:

1. Evaluate sink policy
2. Authorize execution (including execution token checks)
3. Execute only when authorized

## Install

Install MVAR:

```bash
python -m pip install .
```

Install your framework dependencies separately:

```bash
# If using LangChain adapter
python -m pip install langchain

# If using OpenAI adapter
python -m pip install openai

# If using MCP adapter
python -m pip install mcp

# If using AutoGen adapter
python -m pip install pyautogen

# If using CrewAI adapter
python -m pip install crewai
```

## 1) LangChain Wrapper

```python
from mvar_adapters import MVARLangChainAdapter

adapter = MVARLangChainAdapter(policy, graph, strict=True)

safe_tool = adapter.wrap_tool(
    tool_name="bash",
    tool_callable=run_shell,
    action="exec",
)

result = safe_tool(
    command="echo hello",
    source_text="LLM proposed tool call",
    source_is_untrusted=True,
)
```

## 2) OpenAI Tool Call Wrapper

```python
from mvar_adapters import MVAROpenAIAdapter

adapter = MVAROpenAIAdapter(policy, graph, strict=True)

result = adapter.execute_tool_call(
    tool_call={
        "function": {
            "name": "bash",
            "arguments": {"action": "exec", "command": "echo hello"},
        }
    },
    tool_registry={"bash": run_shell},
    source_text="model output",
    source_is_untrusted=True,
)
```

## 3) MCP Tool Call Wrapper

```python
from mvar_adapters import MVARMCPAdapter

adapter = MVARMCPAdapter(policy, graph, strict=True)

result = adapter.execute_mcp_request(
    request={
        "method": "tools/call",
        "params": {
            "name": "bash",
            "arguments": {"action": "exec", "command": "echo hello"},
        },
    },
    tool_registry={"bash": run_shell},
    source_text="external request",
    source_is_untrusted=True,
)
```

## 4) Claude Tool Use Wrapper

```python
from mvar_adapters import MVARClaudeToolAdapter

adapter = MVARClaudeToolAdapter(policy, graph, strict=True)

result = adapter.execute_tool_use(
    tool_use={
        "name": "bash",
        "input": {"action": "exec", "command": "echo hello"},
    },
    tool_registry={"bash": run_shell},
    source_text="tool_use payload",
    source_is_untrusted=True,
)
```

## 5) AutoGen Tool Call Wrapper

```python
from mvar_adapters import MVARAutoGenAdapter

adapter = MVARAutoGenAdapter(policy, graph, strict=True)

result = adapter.execute_tool_call(
    tool_call={
        "function": {
            "name": "bash",
            "arguments": {"action": "exec", "command": "echo hello"},
        }
    },
    tool_registry={"bash": run_shell},
    source_text="model output",
    source_is_untrusted=True,
)
```

## 6) CrewAI Tool Wrapper

```python
from mvar_adapters import MVARCrewAIAdapter

adapter = MVARCrewAIAdapter(policy, graph, strict=True)
safe_tool = adapter.wrap_tool("bash", run_shell, action="exec")

result = safe_tool(
    {"command": "echo hello"},
    source_text="agent proposed tool input",
    source_is_untrusted=True,
)
```

## 7) OpenClaw Dispatch Wrapper

```python
from mvar_adapters import MVAROpenClawAdapter

adapter = MVAROpenClawAdapter(policy, graph, strict=True)
result = adapter.execute_tool_dispatch(
    dispatch={"tool": "bash", "action": "exec", "args": {"command": "echo hello"}},
    tool_registry={"bash": run_shell},
    source_text="OpenClaw planner output",
    source_is_untrusted=True,
)
```

## Conformance and Contract

- Contract: `docs/ADAPTER_SPEC.md`
- Harness: `conformance/pytest_adapter_harness.py`
- Existing tests: `tests/test_first_party_adapters.py`

## Security Defaults

- `strict=True`: raises on `BLOCK`, `STEP_UP`, unresolved fallback targets, or execution errors.
- `source_is_untrusted=True`: fail-closed default for adapter calls.
- Missing explicit target values are treated as unresolved and blocked in strict mode.
