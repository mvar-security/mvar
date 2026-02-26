"""OpenClaw adapter quickstart (illustrative snippet)."""

from mvar_adapters import MVAROpenClawAdapter


def run_shell(command: str = "", **_: object) -> dict:
    return {"ok": True, "command": command}


def example(policy, graph):
    adapter = MVAROpenClawAdapter(policy, graph, strict=True)
    dispatch = {
        "tool": "bash",
        "action": "exec",
        "args": {"command": "echo hello"},
    }
    return adapter.execute_tool_dispatch(
        dispatch=dispatch,
        tool_registry={"bash": run_shell},
        source_text="OpenClaw planner output",
        source_is_untrusted=True,
    )
