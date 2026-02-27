from __future__ import annotations

import json
import importlib
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence

from mvar_adapters.base import AdapterExecutionResult
from mvar_adapters.openai import MVAROpenAIAdapter

try:
    from mvar_core.provenance import ProvenanceGraph
except ImportError:
    from provenance import ProvenanceGraph


@dataclass
class OpenAIToolBatchResult:
    """Summary for one model response containing zero or more tool calls."""

    results: List[AdapterExecutionResult]
    total_calls: int
    executed_calls: int
    blocked_calls: int
    step_up_calls: int


class MVAROpenAIResponsesRuntime:
    """
    Deeper OpenAI integration runtime for tool-calling responses.

    Features:
    - Parses OpenAI Chat Completions and Responses API tool call shapes
    - Supports multi-tool dispatch from a single model response
    - Provides provenance composition for user prompt + retrieved chunks
    - Preserves source/planner context in policy evaluation traces
    """

    def __init__(self, policy: Any, graph: ProvenanceGraph, strict: bool = True, execute_on_step_up: bool = False):
        self.graph = graph
        self.adapter = MVAROpenAIAdapter(
            policy,
            graph,
            strict=strict,
            execute_on_step_up=execute_on_step_up,
        )

    def _resolve_provenance_enums(self) -> tuple[Any, Any]:
        module = importlib.import_module(self.graph.__class__.__module__)
        return getattr(module, "IntegrityLevel"), getattr(module, "ConfidentialityLevel")

    def create_turn_provenance(
        self,
        user_prompt: str,
        retrieved_chunks: Optional[Sequence[str]] = None,
        retrieved_source: str = "retrieved_doc_chunk",
    ) -> str:
        """
        Create a provenance node for a model turn.

        - User prompt is TRUSTED
        - Retrieved chunks are UNTRUSTED
        - Combined turn context is derived conservatively
        """
        IntegrityLevel, ConfidentialityLevel = self._resolve_provenance_enums()

        user_node = self.graph.create_node(
            source="user",
            integrity=IntegrityLevel.TRUSTED,
            confidentiality=ConfidentialityLevel.PUBLIC,
            content=user_prompt,
            taint_tags={"user_input"},
            metadata={},
        )
        parent_ids = [user_node.node_id]

        for idx, chunk in enumerate(retrieved_chunks or []):
            doc_node = self.graph.create_node(
                source="doc",
                integrity=IntegrityLevel.UNTRUSTED,
                confidentiality=ConfidentialityLevel.PUBLIC,
                content=chunk,
                taint_tags={"external_content", "prompt_injection_risk"},
                metadata={
                    "source_context": retrieved_source,
                    "doc_url": f"{retrieved_source}:{idx}",
                },
            )
            parent_ids.append(doc_node.node_id)

        if len(parent_ids) == 1:
            return user_node.node_id

        merged = self.graph.create_derived_node(
            source="openai_turn_context",
            parent_ids=parent_ids,
            content=user_prompt,
            additional_taint_tags={"planner_context"},
            metadata={
                "source_context": f"user_prompt + {retrieved_source}",
                "retrieved_chunks": len(retrieved_chunks or []),
            },
        )
        return merged.node_id

    def execute_response(
        self,
        response_payload: Any,
        tool_registry: Dict[str, Callable[..., Any]],
        provenance_node_id: Optional[str] = None,
        source_text: str = "",
        source_is_untrusted: bool = True,
        source_context: str = "",
        planner_output: str = "",
        execution_token: Optional[Dict[str, Any]] = None,
    ) -> OpenAIToolBatchResult:
        """Execute all tool calls found in an OpenAI response payload via MVAR."""
        normalized_calls = self.extract_tool_calls(response_payload)
        results: List[AdapterExecutionResult] = []

        for tool_call in normalized_calls:
            result = self.adapter.execute_tool_call(
                tool_call=tool_call,
                tool_registry=tool_registry,
                provenance_node_id=provenance_node_id,
                source_text=source_text,
                source_is_untrusted=source_is_untrusted,
                source_context=source_context,
                planner_output=planner_output,
                execution_token=execution_token,
            )
            results.append(result)

        executed = sum(1 for r in results if r.executed)
        blocked = sum(1 for r in results if getattr(r.decision.outcome, "value", "") == "block")
        step_up = sum(1 for r in results if getattr(r.decision.outcome, "value", "") == "step_up")

        return OpenAIToolBatchResult(
            results=results,
            total_calls=len(results),
            executed_calls=executed,
            blocked_calls=blocked,
            step_up_calls=step_up,
        )

    def extract_tool_calls(self, response_payload: Any) -> List[Dict[str, Any]]:
        """Normalize known OpenAI tool-call payload shapes into adapter format."""
        raw_calls: List[Dict[str, Any]] = []

        if isinstance(response_payload, list):
            raw_calls.extend([c for c in response_payload if isinstance(c, dict)])
        elif isinstance(response_payload, dict):
            if isinstance(response_payload.get("tool_calls"), list):
                raw_calls.extend([c for c in response_payload["tool_calls"] if isinstance(c, dict)])

            choices = response_payload.get("choices")
            if isinstance(choices, list):
                for choice in choices:
                    if not isinstance(choice, dict):
                        continue
                    message = choice.get("message", {})
                    if isinstance(message, dict) and isinstance(message.get("tool_calls"), list):
                        raw_calls.extend([c for c in message["tool_calls"] if isinstance(c, dict)])

            output_items = response_payload.get("output")
            if isinstance(output_items, list):
                raw_calls.extend([c for c in output_items if isinstance(c, dict)])

            if isinstance(response_payload.get("function_call"), dict):
                raw_calls.append(response_payload["function_call"])

        normalized: List[Dict[str, Any]] = []
        for call in raw_calls:
            parsed = self._normalize_tool_call(call)
            if parsed is not None:
                normalized.append(parsed)
        return normalized

    def _normalize_tool_call(self, tool_call: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not isinstance(tool_call, dict):
            return None

        function_obj: Dict[str, Any]
        if isinstance(tool_call.get("function"), dict):
            function_obj = dict(tool_call["function"])
        else:
            function_obj = {
                "name": tool_call.get("name") or tool_call.get("tool") or tool_call.get("tool_name"),
                "arguments": tool_call.get("arguments") or tool_call.get("input") or {},
            }

        name = function_obj.get("name")
        if not name:
            return None

        arguments = function_obj.get("arguments", {})
        if isinstance(arguments, str):
            if arguments.strip():
                try:
                    arguments = json.loads(arguments)
                except json.JSONDecodeError:
                    arguments = {"raw": arguments}
            else:
                arguments = {}
        elif not isinstance(arguments, dict):
            arguments = {"value": arguments}

        return {
            "function": {
                "name": name,
                "arguments": arguments,
            }
        }
