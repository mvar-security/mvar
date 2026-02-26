from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from .base import AdapterExecutionResult, MVARExecutionAdapter


class MVAROpenClawAdapter(MVARExecutionAdapter):
    """Wrapper for OpenClaw-style tool dispatch payloads."""

    def execute_tool_dispatch(
        self,
        dispatch: Dict[str, Any],
        tool_registry: Dict[str, Callable[..., Any]],
        provenance_node_id: Optional[str] = None,
        source_text: str = "",
        source_is_untrusted: bool = True,
    ) -> AdapterExecutionResult:
        tool_name = (
            dispatch.get("tool")
            or dispatch.get("name")
            or dispatch.get("tool_name")
        )
        if not tool_name or tool_name not in tool_registry:
            raise ValueError(f"Unknown OpenClaw tool: {tool_name}")

        action = str(dispatch.get("action", "run"))
        arguments = dict(dispatch.get("args") or dispatch.get("arguments") or {})
        resolved_target = (
            dispatch.get("target")
            or arguments.get("target")
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
