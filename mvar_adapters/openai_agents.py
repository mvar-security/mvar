from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional, Sequence

from .base import AdapterExecutionResult, MVARExecutionAdapter


class MVAROpenAIAgentsAdapter(MVARExecutionAdapter):
    """Wrapper for OpenAI Agents SDK-style tool call items."""

    def execute_tool_call_item(
        self,
        tool_call_item: Dict[str, Any],
        tool_registry: Dict[str, Callable[..., Any]],
        provenance_node_id: Optional[str] = None,
        source_text: str = "",
        source_is_untrusted: bool = True,
        source_context: str = "",
        planner_output: str = "",
        execution_token: Optional[Dict[str, Any]] = None,
    ) -> AdapterExecutionResult:
        function_obj = tool_call_item.get("function") if isinstance(tool_call_item.get("function"), dict) else {}
        call_obj = tool_call_item.get("call") if isinstance(tool_call_item.get("call"), dict) else {}

        tool_name = (
            tool_call_item.get("name")
            or tool_call_item.get("tool_name")
            or tool_call_item.get("tool")
            or function_obj.get("name")
            or call_obj.get("name")
        )
        if not tool_name or tool_name not in tool_registry:
            raise ValueError(f"Unknown OpenAI Agents tool: {tool_name}")

        raw_args = (
            tool_call_item.get("arguments")
            or tool_call_item.get("input")
            or tool_call_item.get("args")
            or function_obj.get("arguments")
            or call_obj.get("arguments")
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

        action = str(tool_call_item.get("action") or arguments.get("action") or "run")
        resolved_target = (
            tool_call_item.get("target")
            or arguments.get("target")
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

    def execute_tool_call_items(
        self,
        tool_call_items: Sequence[Dict[str, Any]],
        tool_registry: Dict[str, Callable[..., Any]],
        provenance_node_id: Optional[str] = None,
        source_text: str = "",
        source_is_untrusted: bool = True,
        source_context: str = "",
        planner_output: str = "",
    ) -> List[AdapterExecutionResult]:
        results: List[AdapterExecutionResult] = []
        for item in tool_call_items:
            results.append(
                self.execute_tool_call_item(
                    tool_call_item=item,
                    tool_registry=tool_registry,
                    provenance_node_id=provenance_node_id,
                    source_text=source_text,
                    source_is_untrusted=source_is_untrusted,
                    source_context=source_context,
                    planner_output=planner_output,
                )
            )
        return results

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
