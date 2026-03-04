from __future__ import annotations

import json
from typing import Any, Callable, Dict, Optional

from .base import AdapterExecutionResult, MVARExecutionAdapter


class MVARGoogleADKAdapter(MVARExecutionAdapter):
    """Wrapper for Google ADK-style tool invocation payloads."""

    def execute_tool_invocation(
        self,
        invocation: Dict[str, Any],
        tool_registry: Dict[str, Callable[..., Any]],
        provenance_node_id: Optional[str] = None,
        source_text: str = "",
        source_is_untrusted: bool = True,
    ) -> AdapterExecutionResult:
        function_obj = invocation.get("function") if isinstance(invocation.get("function"), dict) else {}
        tool_name = (
            invocation.get("tool_name")
            or invocation.get("name")
            or invocation.get("tool")
            or function_obj.get("name")
        )
        if not tool_name or tool_name not in tool_registry:
            raise ValueError(f"Unknown Google ADK tool: {tool_name}")

        raw_args = (
            invocation.get("args")
            or invocation.get("arguments")
            or invocation.get("input")
            or function_obj.get("arguments")
            or {}
        )

        if isinstance(raw_args, str):
            try:
                arguments = json.loads(raw_args) if raw_args.strip() else {}
            except json.JSONDecodeError:
                arguments = {"raw": raw_args}
        elif isinstance(raw_args, dict):
            arguments = raw_args
        else:
            arguments = {"value": raw_args}

        action = str(invocation.get("action") or arguments.get("action") or "run")
        resolved_target = (
            invocation.get("target")
            or arguments.get("target")
            or arguments.get("command")
            or arguments.get("path")
            or arguments.get("resource")
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
