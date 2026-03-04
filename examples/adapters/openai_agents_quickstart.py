"""OpenAI Agents SDK adapter quickstart (illustrative snippet)."""

from mvar_adapters import MVAROpenAIAgentsAdapter


def run_shell(action: str = "run", command: str = "", **_: object) -> dict:
    return {"ok": True, "action": action, "command": command}


def example(policy, graph):
    adapter = MVAROpenAIAgentsAdapter(policy, graph, strict=True)
    tool_call_item = {
        "type": "tool_call",
        "name": "bash",
        "arguments": {
            "action": "exec",
            "command": "echo hello",
        },
    }
    return adapter.execute_tool_call_item(
        tool_call_item=tool_call_item,
        tool_registry={"bash": run_shell},
        source_text="OpenAI Agents planner output",
        source_is_untrusted=True,
    )
