"""CrewAI adapter quickstart (illustrative snippet)."""

from mvar_adapters import MVARCrewAIAdapter


def run_shell(command: str = "", **_: object) -> dict:
    return {"ok": True, "command": command}


def example(policy, graph):
    adapter = MVARCrewAIAdapter(policy, graph, strict=True)
    safe_tool = adapter.wrap_tool("bash", run_shell, action="exec")

    return safe_tool(
        {"command": "echo hello"},
        source_text="agent proposed tool input",
        source_is_untrusted=True,
    )
