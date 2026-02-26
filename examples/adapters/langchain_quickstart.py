"""LangChain adapter quickstart (illustrative snippet)."""

from mvar_adapters import MVARLangChainAdapter


def run_shell(command: str, **_: object) -> dict:
    return {"ok": True, "command": command}


def example(policy, graph):
    adapter = MVARLangChainAdapter(policy, graph, strict=True)
    safe_tool = adapter.wrap_tool("bash", run_shell, action="exec")

    return safe_tool(
        command="echo hello",
        source_text="LLM proposed tool call",
        source_is_untrusted=True,
    )
