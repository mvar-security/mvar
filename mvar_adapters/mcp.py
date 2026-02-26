from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from .base import AdapterExecutionResult, MVARExecutionAdapter


class MVARMCPAdapter(MVARExecutionAdapter):
    """Wrapper for MCP tool call requests."""

    def execute_mcp_request(
        self,
        request: Dict[str, Any],
        tool_registry: Dict[str, Callable[..., Any]],
        provenance_node_id: Optional[str] = None,
        source_text: str = "",
        source_is_untrusted: bool = True,
    ) -> AdapterExecutionResult:
        method = request.get("method", "tools/call")
        params = request.get("params", {})

        if method != "tools/call":
            raise ValueError(f"Unsupported MCP method: {method}")

        tool_name = params.get("name")
        if not tool_name or tool_name not in tool_registry:
            raise ValueError(f"Unknown MCP tool: {tool_name}")

        arguments = params.get("arguments", {})
        action = str(arguments.get("action", "run"))
        resolved_target = (
            arguments.get("target")
            or arguments.get("command")
            or arguments.get("path")
        )
        target_is_fallback = resolved_target is None
        target = str(resolved_target or tool_name)

        return self.enforce_and_execute(
            tool=tool_name,
            action=action,
            target=target,
            execute_fn=lambda: tool_registry[tool_name](**arguments),
            provenance_node_id=provenance_node_id,
            source_text=source_text,
            source_is_untrusted=source_is_untrusted,
            parameters=arguments,
            target_is_fallback=target_is_fallback,
        )
