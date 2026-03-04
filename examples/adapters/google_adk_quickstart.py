"""Google ADK adapter quickstart (illustrative snippet)."""

from mvar_adapters import MVARGoogleADKAdapter


def run_shell(action: str = "run", command: str = "", **_: object) -> dict:
    return {"ok": True, "action": action, "command": command}


def example(policy, graph):
    adapter = MVARGoogleADKAdapter(policy, graph, strict=True)
    invocation = {
        "tool_name": "bash",
        "args": {
            "action": "exec",
            "command": "echo hello",
        },
    }
    return adapter.execute_tool_invocation(
        invocation=invocation,
        tool_registry={"bash": run_shell},
        source_text="Google ADK planner output",
        source_is_untrusted=True,
    )
