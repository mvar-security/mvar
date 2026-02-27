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
        source_context: str = "",
        planner_output: str = "",
        execution_token: Optional[Dict[str, Any]] = None,
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

        result = self.enforce_and_execute(
            tool=tool_name,
            action=action,
            target=target,
            execute_fn=lambda: tool_registry[tool_name](**arguments),
            provenance_node_id=provenance_node_id,
            source_text=source_text,
            source_is_untrusted=source_is_untrusted,
            parameters=arguments,
            execution_token=execution_token,
            target_is_fallback=target_is_fallback,
        )
        self._append_context_trace(
            result,
            source_context=source_context,
            planner_output=planner_output,
        )
        return result

    @staticmethod
    def _append_context_trace(
        result: AdapterExecutionResult,
        source_context: str,
        planner_output: str,
    ) -> None:
        trace = getattr(result.decision, "evaluation_trace", None)
        if not isinstance(trace, list):
            return
        if source_context:
            trace.append(f"source_context: {source_context}")
        if planner_output:
            trace.append(f"planner_output: {planner_output}")
