"""AutoGen adapter quickstart (illustrative snippet)."""

from mvar_adapters import MVARAutoGenAdapter


def run_shell(action: str = "run", command: str = "", **_: object) -> dict:
    return {"ok": True, "action": action, "command": command}


def example(policy, graph):
    adapter = MVARAutoGenAdapter(policy, graph, strict=True)

    return adapter.execute_tool_call(
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
