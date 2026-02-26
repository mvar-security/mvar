from __future__ import annotations

import json
from typing import Any, Callable, Dict, Optional

from .base import AdapterExecutionResult, MVARExecutionAdapter


class MVAROpenAIAdapter(MVARExecutionAdapter):
    """Wrapper for OpenAI-style function/tool call dictionaries."""

    def execute_tool_call(
        self,
        tool_call: Dict[str, Any],
        tool_registry: Dict[str, Callable[..., Any]],
        provenance_node_id: Optional[str] = None,
        source_text: str = "",
        source_is_untrusted: bool = True,
    ) -> AdapterExecutionResult:
        function_obj = tool_call.get("function", tool_call)
        tool_name = function_obj.get("name")
        if not tool_name or tool_name not in tool_registry:
            raise ValueError(f"Unknown tool call: {tool_name}")

        raw_args = function_obj.get("arguments", {})
        if isinstance(raw_args, str):
            try:
                arguments = json.loads(raw_args) if raw_args.strip() else {}
            except json.JSONDecodeError:
                arguments = {"raw": raw_args}
        elif isinstance(raw_args, dict):
            arguments = raw_args
        else:
            arguments = {"value": raw_args}

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
