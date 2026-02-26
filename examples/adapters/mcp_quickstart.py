"""MCP adapter quickstart (illustrative snippet)."""

from mvar_adapters import MVARMCPAdapter


def run_shell(action: str = "run", command: str = "", **_: object) -> dict:
    return {"ok": True, "action": action, "command": command}


def example(policy, graph):
    adapter = MVARMCPAdapter(policy, graph, strict=True)

    return adapter.execute_mcp_request(
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
